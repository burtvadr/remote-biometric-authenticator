package io.github.burtvadr.rba.protocol

import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import io.github.burtvadr.rba.protocol.Cbor.Value

/** V2 wire primitives only. Never falls back to V1. Session/schema checks are separate. */
object V2Wire {
    const val VERSION = 2
    const val HEADER_LEN = 13
    const val MAX_PAYLOAD = 65_536
    private const val MAX_DEPTH = 8
    private const val MAX_ITEMS = 1024
    private const val MAX_CONTAINER = 32
    class Invalid : IllegalArgumentException("invalid V2 wire data")
    data class Header(val messageType: Int, val payloadLen: Int)
    private fun check(ok: Boolean) { if (!ok) throw Invalid() }
    private fun known(t: Int) = t in 10..24 || t in 30..38
    private fun octet(b: Byte) = b.toInt() and 255
    fun parseHeader(h: ByteArray): Header {
        check(h.size == HEADER_LEN)
        check(h[0] == 80.toByte() && h[1] == 65.toByte() && h[2] == 70.toByte() && h[3] == 50.toByte())
        check(octet(h[4]) == VERSION && h[7] == 0.toByte() && h[8] == 0.toByte())
        val t = octet(h[5]) * 256 + octet(h[6])
        var n = 0L
        for (i in 9..12) n = (n shl 8) or octet(h[i]).toLong()
        check(known(t) && n in 1..MAX_PAYLOAD.toLong())
        return Header(t, n.toInt())
    }
    private fun cmp(a: ByteArray, b: ByteArray): Int {
        for (i in 0 until minOf(a.size, b.size)) {
            val d = octet(a[i]) - octet(b[i]); if (d != 0) return d
        }
        return a.size.compareTo(b.size)
    }
    private class Decoder(val data: ByteArray) {
        var pos = 0
        var items = 0
        fun take(n: Int): ByteArray {
            check(n >= 0 && n <= data.size - pos)
            val b = data.copyOfRange(pos, pos + n); pos += n; return b
        }
        fun byte(): Int { check(pos < data.size); return octet(data[pos++]) }
        fun arg(ai: Int): ULong {
            if (ai in 0..23) return ai.toULong()
            val (n, min) = when (ai) {
                24 -> 1 to 24uL; 25 -> 2 to 256uL; 26 -> 4 to 65536uL; 27 -> 8 to 4294967296uL
                else -> throw Invalid()
            }
            var v = 0uL
            repeat(n) { v = (v shl 8) or byte().toULong() }
            check(v >= min); return v
        }
        fun value(depth: Int): Value {
            check(depth <= MAX_DEPTH && ++items <= MAX_ITEMS)
            val h = byte(); val major = h shr 5
            check(major == 0 || major in 2..5)
            val a = arg(h and 31)
            if (major == 0) return Value.Uint(a.toLong())
            check(a <= MAX_PAYLOAD.toULong()); val n = a.toInt()
            return when (major) {
                2 -> Value.Bytes(take(n))
                3 -> {
                    val raw = take(n)
                    val s = try { Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(raw)).toString() }
                    catch (_: java.nio.charset.CharacterCodingException) { throw Invalid() }
                    Value.Text(s)
                }
                4, 5 -> {
                    val width = if (major == 4) 1 else 2
                    check(n <= MAX_CONTAINER && n * width <= data.size - pos && n * width <= MAX_ITEMS - items)
                    if (major == 4) Value.Arr(List(n) { value(depth + 1) })
                    else {
                        var prev: ByteArray? = null
                        Value.Map(List(n) {
                            val start = pos; val k = value(depth + 1); check(k is Value.Text)
                            val raw = data.copyOfRange(start, pos)
                            prev?.let { check(cmp(it, raw) < 0) }; prev = raw
                            k to value(depth + 1)
                        })
                    }
                }
                else -> throw Invalid()
            }
        }
    }
    /** Structural validation only; exact schema, NFC, key and state checks are mandatory separately. */
    fun decodePayload(bytes: ByteArray): Value.Map {
        check(bytes.size in 1..MAX_PAYLOAD)
        val d = Decoder(bytes); val v = d.value(0)
        check(d.pos == bytes.size)
        return v as? Value.Map ?: throw Invalid()
    }
    /** Bound the encoded size before encoding. Reject unpaired UTF-16 surrogates. */
    fun encodePayload(v: Value): ByteArray {
        var items = 0
        fun head(n: ULong): Int = when { n < 24uL -> 1; n <= 255uL -> 2; n <= 65535uL -> 3; n <= 4294967295uL -> 5; else -> 9 }
        fun size(x: Value, depth: Int): Int {
            check(depth <= MAX_DEPTH && ++items <= MAX_ITEMS)
            val n = when (x) {
                is Value.Uint -> head(x.value.toULong())
                is Value.Bytes -> { check(x.value.size <= MAX_PAYLOAD); head(x.value.size.toULong()) + x.value.size }
                is Value.Text -> {
                    check(x.value.length <= MAX_PAYLOAD)
                    // Count strict UTF-8 bytes without allocating a second buffer.
                    var bytes = 0
                    var i = 0
                    while (i < x.value.length) {
                        val c = x.value[i++]
                        bytes += when {
                            c.code < 0x80 -> 1
                            c.code < 0x800 -> 2
                            Character.isHighSurrogate(c) -> {
                                check(i < x.value.length && Character.isLowSurrogate(x.value[i]))
                                i++; 4
                            }
                            Character.isLowSurrogate(c) -> throw Invalid()
                            else -> 3
                        }
                        check(bytes <= MAX_PAYLOAD)
                    }
                    head(bytes.toULong()) + bytes
                }
                is Value.Arr -> {
                    check(x.items.size <= MAX_CONTAINER); var n = head(x.items.size.toULong())
                    for (e in x.items) { n += size(e, depth+1); check(n <= MAX_PAYLOAD) }; n
                }
                is Value.Map -> {
                    check(x.entries.size <= MAX_CONTAINER); var n = head(x.entries.size.toULong())
                    for ((k,e) in x.entries) { check(k is Value.Text); n += size(k,depth+1) + size(e,depth+1); check(n <= MAX_PAYLOAD) }; n
                }
                else -> throw Invalid()
            }
            check(n <= MAX_PAYLOAD); return n
        }
        check(v is Value.Map); size(v,0)
        val bytes = Cbor.encode(v); decodePayload(bytes); return bytes
    }
    fun encodeFrame(messageType: Int, payload: Value): ByteArray {
        check(known(messageType)); val body = encodePayload(payload)
        return ByteBuffer.allocate(HEADER_LEN + body.size).put(byteArrayOf(80,65,70,50)).put(VERSION.toByte())
            .putShort(messageType.toShort()).putShort(0).putInt(body.size).put(body).array()
    }
    /** Exact single-frame read, on a carrier whose caller enforces absolute deadlines. */
    fun readFrame(input: InputStream): Pair<Header, Value.Map> {
        fun exact(n: Int): ByteArray {
            val out = ByteArray(n); var p = 0
            while (p < n) { val k = input.read(out,p,n-p); if (k <= 0) throw java.io.EOFException(); p += k }
            return out
        }
        val h = parseHeader(exact(HEADER_LEN)); return h to decodePayload(exact(h.payloadLen))
    }
}
