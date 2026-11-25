package io.github.burtvadr.rba.keystore

import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/** Standalone JVM checks for encoding helpers; not Android hardware tests. */
internal object V2KeyEncodingChecks {
    fun run(): Int {
        var checks=0
        fun ok(value:Boolean){check(value);checks++}
        fun rejects(block:()->Unit){ok(runCatching(block).isFailure)}
        fun der(r:ByteArray,s:ByteArray)=byteArrayOf(0x30,(4+r.size+s.size).toByte(),2,r.size.toByte())+r+byteArrayOf(2,s.size.toByte())+s
        val generator=KeyPairGenerator.getInstance("EC").apply{initialize(ECGenParameterSpec("secp256r1"))}
        val keys=generator.generateKeyPair();val point=V2KeyEncoding.point(keys.public as ECPublicKey)
        ok(point.size==65&&point[0]==4.toByte())
        ok(BigInteger(1,point.copyOfRange(1,33))==(keys.public as ECPublicKey).w.affineX)
        ok(BigInteger(1,point.copyOfRange(33,65))==(keys.public as ECPublicKey).w.affineY)
        rejects{V2KeyEncoding.point(KeyPairGenerator.getInstance("EC").apply{initialize(ECGenParameterSpec("secp384r1"))}.generateKeyPair().public as ECPublicKey)}
        val msg="V2 encoding test".toByteArray()
        repeat(16){
            val signed=Signature.getInstance("SHA256withECDSA").apply{initSign(keys.private);update(msg)}.sign()
            val raw=V2KeyEncoding.rawSignature(signed);ok(raw.size==64)
            val rebuilt=der(BigInteger(1,raw.copyOfRange(0,32)).toByteArray(),BigInteger(1,raw.copyOfRange(32,64)).toByteArray())
            ok(signed.contentEquals(rebuilt))
            ok(Signature.getInstance("SHA256withECDSA").apply{initVerify(keys.public);update(msg)}.verify(rebuilt))
        }
        val simple=der(byteArrayOf(1),byteArrayOf(2));ok(V2KeyEncoding.rawSignature(simple).let{it[31]==1.toByte()&&it[63]==2.toByte()})
        for(bad in listOf(simple+byteArrayOf(0),simple.copyOf(7),der(byteArrayOf(0),byteArrayOf(1)),der(byteArrayOf(-1),byteArrayOf(1)),der(byteArrayOf(0,1),byteArrayOf(1)),der(ByteArray(33){1},byteArrayOf(1)),der(BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",16).toByteArray(),byteArrayOf(1)))) rejects{V2KeyEncoding.rawSignature(bad)}
        val challenge=ByteArray(32){it.toByte()}
        fun tlv(tag:Int,body:ByteArray)=byteArrayOf(tag.toByte(),body.size.toByte())+body
        val body=byteArrayOf(2,1,3,10,1,1,2,1,4,10,1,1)+tlv(4,challenge)+byteArrayOf(4,0,0x30,0,0x30,0)
        val extension=tlv(4,tlv(0x30,body));ok(V2KeyEncoding.attestationChallenge(extension).contentEquals(challenge))
        for(bad in listOf(extension+byteArrayOf(0),extension.copyOf(extension.size-1),extension.copyOf().apply{this[0]=0x30},extension.copyOf().apply{this[16]=3},extension.copyOf().apply{this[17]=31})) rejects{V2KeyEncoding.attestationChallenge(bad)}
        return checks
    }
}
fun main(){println("PASS: ${V2KeyEncodingChecks.run()} V2 key encoding checks")}
