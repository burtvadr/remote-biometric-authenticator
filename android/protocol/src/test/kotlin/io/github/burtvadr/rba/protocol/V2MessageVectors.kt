package io.github.burtvadr.rba.protocol

import java.io.File
import java.io.ByteArrayInputStream
import io.github.burtvadr.rba.protocol.Cbor.Value

object V2MessageVectors {
    private fun bytes(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun domain(s: String) = V2Message.Domain.entries.single { it.label == s }
    fun run(dir: File): Int {
        var count = 0
        for (line in File(dir,"v2-message.tsv").readLines().filterNot { it.startsWith('#') }) {
            val (name,mode,data,extra) = line.split('\t'); val raw = bytes(data)
            when(mode) {
                "accept" -> {
                    val input = ByteArrayInputStream(raw); val m = V2Message.Message.read(input)
                    check(m.encode().contentEquals(raw) && input.available() == 0) { name }
                    // Returned maps and byte arrays are copies, never the internal signed representation.
                    val payload = m.payload()
                    (payload.entries.firstOrNull { it.second is Value.Bytes }?.second as? Value.Bytes)?.value?.fill(99)
                    check(m.encode().contentEquals(raw)) { "$name: mutable alias" }
                }
                "reject" -> check(runCatching { V2Message.Message.read(ByteArrayInputStream(raw)) }.exceptionOrNull() is V2Wire.Invalid) { name }
                "transcript" -> {
                    val (t,h) = extra.split(':'); val core = V2Wire.decodePayload(raw); val d = domain(name)
                    check(V2Message.transcript(d,core).contentEquals(bytes(t))) { name }
                    check(V2Message.hash(d,core).contentEquals(bytes(h))) { name }
                    val wrong = if (d == V2Message.Domain.ATTEST) V2Message.Domain.POLICY else V2Message.Domain.ATTEST
                    check(runCatching { V2Message.transcript(wrong,core) }.exceptionOrNull() is V2Wire.Invalid) { name }
                }
                "verify","bad-signature" -> {
                    val (d,k,s) = extra.split(':'); val core = V2Wire.decodePayload(raw); val key = bytes(k); val sig = bytes(s)
                    val result = runCatching { V2Message.verify(domain(d),core,key,sig) }
                    if (mode == "verify") {
                        check(result.isSuccess) { "$name: ${result.exceptionOrNull()}" }
                        val changed = Value.Map(core.entries.map { (a,b) -> a to if (a == Value.Text("channel")) Value.Bytes(ByteArray(32){99}) else b })
                        check(runCatching { V2Message.verify(domain(d),changed,key,sig) }.exceptionOrNull() is V2Wire.Invalid) { "$name: channel tamper" }
                    } else check(result.exceptionOrNull() is V2Wire.Invalid) { name }
                }
                else -> error("unexpected fixture mode $mode")
            }
            count++
        }
        check(count >= 250)
        val expected = BooleanArray(0x110000)
        val repertoire = File(dir.parentFile, "text-profile/rba-display-text-1.tsv")
        for (line in repertoire.readLines().filterNot { it.startsWith('#') }) {
            val (lo, hi) = line.split('\t').map { it.toInt(16) }
            for (cp in lo..hi) expected[cp] = true
        }
        for (cp in expected.indices) {
            check(V2TextProfile.allowed(cp) == expected[cp]) { "display repertoire U+${cp.toString(16)}" }
        }
        check(!V2TextProfile.label("\uD800", 128))
        check(!V2TextProfile.label("\uDC00", 128))
        println("PASS: display repertoire exhaustive scalar-table comparison (1114112 code points)")
        return count
    }
}
