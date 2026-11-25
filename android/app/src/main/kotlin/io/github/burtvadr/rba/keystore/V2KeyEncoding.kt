package io.github.burtvadr.rba.keystore

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.interfaces.ECPublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec

/** Public-key and signature encoding only. Never handles private scalars. */
internal object V2KeyEncoding {
    private val p256 by lazy {
        AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
            .getParameterSpec(ECParameterSpec::class.java)
    }
    private val order = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
    private fun fixed(n: BigInteger): ByteArray {
        require(n.signum() >= 0 && n.bitLength() <= 256)
        val value = n.toByteArray()
        val start = if (value.size == 33) 1 else 0
        return ByteArray(32).also { value.copyInto(it, 32 - (value.size - start), start) }
    }
    fun point(key: ECPublicKey): ByteArray {
        val p = p256
        val k = key.params
        val prime = (p.curve.field as ECFieldFp).p
        require(k.curve == p.curve && k.generator == p.generator && k.order == p.order && k.cofactor == p.cofactor)
        val x = key.w.affineX; val y = key.w.affineY
        require(x.signum() >= 0 && y.signum() >= 0 && x < prime && y < prime)
        require(y.multiply(y).mod(prime) == x.multiply(x).multiply(x).add(p.curve.a.multiply(x)).add(p.curve.b).mod(prime))
        return byteArrayOf(4) + fixed(x) + fixed(y)
    }
    /** Read only the challenge field of Android's KeyDescription extension.
     * X509Certificate.getExtensionValue returns an outer DER OCTET STRING.
     * This is a local generation consistency check, NOT a path or policy verifier. */
    fun attestationChallenge(extension: ByteArray): ByteArray {
        require(extension.size in 1..8192)
        class Reader(private val bytes: ByteArray) {
            private var offset = 0
            fun read(tag: Int): ByteArray {
                require(offset + 2 <= bytes.size && (bytes[offset++].toInt() and 255) == tag)
                val first = bytes[offset++].toInt() and 255
                var length = first
                if (first >= 128) {
                    val count = first and 127
                    require(count in 1..2 && count <= bytes.size - offset && bytes[offset] != 0.toByte())
                    length = 0
                    repeat(count) { length = (length shl 8) or (bytes[offset++].toInt() and 255) }
                    require(length >= 128)
                }
                require(length <= bytes.size - offset)
                return bytes.copyOfRange(offset, offset + length).also { offset += length }
            }
            fun end() = require(offset == bytes.size)
        }
        val outer = Reader(extension)
        val inner = Reader(outer.read(4)); outer.end()
        val description = Reader(inner.read(0x30)); inner.end()
        for (tag in listOf(2,10,2,10)) require(description.read(tag).size in 1..5)
        val challenge = description.read(4)
        require(challenge.size == 32)
        // The host validates the rest, including every authorization field.
        return challenge
    }
    /** P-256 ECDSA has a short-form DER SEQUENCE of two positive minimal
     * INTEGERs. Do not truncate, accept trailing bytes, or normalize malformed DER. */
    fun rawSignature(der: ByteArray): ByteArray {
        require(der.size in 8..72 && der[0] == 0x30.toByte() && der[1].toInt() == der.size - 2)
        var offset = 2
        fun scalar(): ByteArray {
            require(offset + 2 <= der.size && der[offset++] == 2.toByte())
            val length = der[offset++].toInt()
            require(length in 1..33 && length <= der.size - offset)
            require(der[offset].toInt() >= 0)
            if (length > 1 && der[offset] == 0.toByte()) require(der[offset + 1].toInt() < 0)
            val number = BigInteger(1, der.copyOfRange(offset, offset + length))
            offset += length
            require(number.signum() > 0 && number < order)
            return fixed(number)
        }
        val raw = scalar() + scalar()
        require(offset == der.size)
        return raw
    }
}
