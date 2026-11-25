package io.github.burtvadr.rba.ui.v2

import io.github.burtvadr.rba.protocol.Cbor.Value
import io.github.burtvadr.rba.protocol.V2Message
import java.io.File
import java.io.ByteArrayInputStream

internal object V2OperatorTextChecks {
    fun run(vectors: File): Int {
        val frames = vectors.readLines().filterNot { it.startsWith('#') }.map { it.split('\t') }
        fun frame(name: String): V2Message.Message {
            val row = frames.single { it[0] == name }
            check(row[1] == "accept")
            val bytes = row[2].chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            return V2Message.Message.read(ByteArrayInputStream(bytes))
        }
        var count = 0
        fun verify(ok: Boolean) { check(ok); count++ }
        val core = frame("msg-12").payload()["core"] as Value.Map
        val auth = V2OperatorText.authentication(core)
        for (field in listOf("host_id", "credential_id", "approver", "target"))
            verify(V2OperatorText.hex((core[field] as Value.Bytes).value) in auth)
        for (field in listOf("approver_label", "target_label"))
            verify("\u2068${(core[field] as Value.Text).value}\u2069" in auth)
        val scope = core["scope"] as Value.Map
        for (field in listOf("purpose", "service", "operation")) verify((scope[field] as Value.Text).value in auth)
        val context = core["context"] as Value.Map
        verify((context["source"] as Value.Text).value in auth)
        verify((context["detail"] as Value.Text).value in auth)
        verify(V2OperatorText.hex((context["interaction_id"] as Value.Bytes).value) in auth)
        verify((core["expires_at"] as Value.Uint).asBigInteger().toString() in auth)
        for (name in listOf("host_nonce", "device_nonce", "channel", "challenge"))
            verify(V2OperatorText.hex((core[name] as Value.Bytes).value) !in auth)
        val offer = frame("msg-35")
        val p = offer.payload()
        val offerHash = V2Message.hash(V2Message.Domain.ENROLLOFFER, p)
        val policy = V2OperatorText.policy(offer, offerHash)
        verify(V2OperatorText.hex(offerHash) in policy)
        for (secret in listOf("token", "receipt")) verify(V2OperatorText.hex((p[secret] as Value.Bytes).value) !in policy)
        for (g in (p["grants"] as Value.Arr).items) {
            g as Value.Map
            for (field in listOf("credential_id", "approver", "target")) verify(V2OperatorText.hex((g[field] as Value.Bytes).value) in policy)
            val s = g["scope"] as Value.Map
            for (field in listOf("purpose", "service", "operation")) verify((s[field] as Value.Text).value in policy)
        }
        val update = frame("msg-20")
        val digest = (update.payload()["digest"] as Value.Bytes).value
        verify(V2OperatorText.hex(digest) in V2OperatorText.policy(update, digest))
        verify(runCatching { V2OperatorText.policy(frame("msg-12"), digest) }.isFailure)
        println("PASS: $count V2 operator presentation checks")
        return count
    }
}
fun main(args: Array<String>) { V2OperatorTextChecks.run(File(args.single())) }
