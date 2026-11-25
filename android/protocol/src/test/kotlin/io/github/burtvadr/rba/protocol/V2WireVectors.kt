package io.github.burtvadr.rba.protocol

import java.io.File
import java.io.ByteArrayInputStream
import io.github.burtvadr.rba.protocol.Cbor.Value

/** Also runnable without Gradle or the Android SDK. */
object V2WireVectors {
    fun run(dir: File): Int {
        var count = 0
        for (line in File(dir, "v2-wire.tsv").readLines().filterNot { it.startsWith('#') }) {
            val (name, expected, hex) = line.split('\t')
            val raw = hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            val input = ByteArrayInputStream(raw)
            val result = runCatching { V2Wire.readFrame(input) }
            when (expected) {
                "accept" -> {
                    val (header, body) = result.getOrElse { error("$name: $it") }
                    check(V2Wire.encodeFrame(header.messageType, body).contentEquals(raw)) { name }
                    check(input.available() == 0) { name }
                }
                "bad-header" -> {
                    check(result.exceptionOrNull() is V2Wire.Invalid) { name }
                    check(raw.size - input.available() == V2Wire.HEADER_LEN) { name }
                }
                "reject" -> check(result.exceptionOrNull() is V2Wire.Invalid || result.exceptionOrNull() is java.io.EOFException) { name }
                else -> error("unknown fixture mode $expected")
            }
            count++
        }
        check(count >= 60)
        val v = Cbor.ofMap("v" to Cbor.uint(2))
        val a = V2Wire.encodeFrame(10, v); val b = V2Wire.encodeFrame(11, v)
        val input = ByteArrayInputStream(a + b)
        check(V2Wire.readFrame(input).first.messageType == 10 && input.available() == b.size)
        check(V2Wire.readFrame(input).first.messageType == 11 && input.available() == 0)
        count++
        val bad = listOf(Value.Bool(true), Cbor.ofMap("x" to Value.Nint(0)),
            Cbor.ofMap("x" to Value.Bytes(ByteArray(65537))), Cbor.ofMap("x" to Value.Arr(List(33) { Value.Uint(0) })),
            Value.Map(listOf(Value.Text("z") to Value.Uint(0), Value.Text("a") to Value.Uint(0))),
            Value.Map(listOf(Value.Text("x") to Value.Uint(0), Value.Text("x") to Value.Uint(1))),
            Cbor.ofMap("x" to Value.Text("\uD800")))
        for (x in bad) { check(runCatching { V2Wire.encodeFrame(10,x) }.exceptionOrNull() is V2Wire.Invalid); count++ }
        check(runCatching { V2Wire.encodeFrame(25,v) }.exceptionOrNull() is V2Wire.Invalid); count++
        val max = V2Wire.decodePayload(byteArrayOf(0xa1.toByte(), 0x61, 0x78, 0x1b) + ByteArray(8) { 0xff.toByte() })
        check((max["x"] as Value.Uint).value.toULong() == ULong.MAX_VALUE); count++
        check(V2Wire.encodePayload(Cbor.ofMap("x" to Cbor.uint(256))).contentEquals(byteArrayOf(0xa1.toByte(), 0x61, 0x78, 0x19, 0x01, 0x00))); count++
        return count
    }
}
