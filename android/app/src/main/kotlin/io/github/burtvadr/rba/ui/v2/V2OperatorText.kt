package io.github.burtvadr.rba.ui.v2

import io.github.burtvadr.rba.protocol.Cbor.Value
import io.github.burtvadr.rba.protocol.V2Message
import io.github.burtvadr.rba.protocol.V2Enrollment

/** Render only explicitly selected verified facts. Never render an entire wire
 * message: enrollment offers also contain revocation tokens and receipts. */
internal object V2OperatorText {
    fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it.toInt() and 255) }
    private fun field(v: Value, name: String): Value = checkNotNull((v as Value.Map)[name])
    private fun text(v: Value, name: String) = (field(v, name) as Value.Text).value
    private fun id(v: Value, name: String) = hex((field(v, name) as Value.Bytes).value)
    private fun uint(v: Value, name: String) = (field(v, name) as Value.Uint).asBigInteger().toString()
    private fun scope(v: Value): String = "Purpose: ${text(v, "purpose")}\nService: ${text(v, "service")}\nOperation: ${text(v, "operation")}"
    // Directional isolates keep untrusted labels from visually reordering the
    // surrounding fixed UI captions, without changing the signed input.
    private fun isolate(s: String) = "\u2068$s\u2069"
    fun authentication(core: Value.Map): String = buildString {
        appendLine("Enrolled host ID: ${id(core, "host_id")}")
        appendLine("Credential: ${id(core, "credential_id")}")
        appendLine("Approver: ${isolate(text(core, "approver_label"))}")
        appendLine("Approver ID: ${id(core, "approver")}")
        appendLine("Target: ${isolate(text(core, "target_label"))}")
        appendLine("Target ID: ${id(core, "target")}")
        appendLine(scope(field(core, "scope")))
        val context = field(core, "context")
        appendLine("Context source: ${text(context, "source")}")
        appendLine("Context detail: ${isolate(text(context, "detail"))}")
        appendLine("Interaction: ${id(context, "interaction_id")}")
        appendLine("Policy revision: ${uint(core, "policy_revision")}")
        appendLine("Expires at (Unix seconds): ${uint(core, "expires_at")}")
        append("Enter the number shown by your own host interaction. If anything differs, decline.")
    }
    fun enrollment(f: V2Enrollment.Confirmation): String = buildString {
        appendLine("Pairing code confirmed. Compare these fingerprints with the host before approving.")
        appendLine("Host certificate SHA-256: ${hex(f.hostCert)}")
        appendLine("Host public key SHA-256: ${hex(f.hostKeyHash)}")
        appendLine("Provisional device certificate SHA-256: ${hex(f.provisionalCert)}")
        appendLine("Provisional device public key SHA-256: ${hex(f.provisionalKeyHash)}")
        appendLine("New transport key SHA-256: ${hex(f.transportKeyHash)}")
        appendLine("New biometric key SHA-256: ${hex(f.biometricKeyHash)}")
        append("Enrollment context SHA-256: ${hex(f.contextHash)}")
    }
    fun policy(message: V2Message.Message, digest: ByteArray): String {
        require(message.kind == V2Message.Kind.POLICYOFFER || message.kind == V2Message.Kind.ENROLLOFFER)
        val p = message.payload()
        val grants = (field(p, "grants") as Value.Arr).items
        return buildString {
            appendLine("Revision: ${uint(p, "revision")}")
            appendLine("${if (message.kind == V2Message.Kind.ENROLLOFFER) "Enrollment offer" else "Policy"} SHA-256: ${hex(digest)}")
            if (grants.isEmpty()) appendLine("No permissions (deny all).")
            for ((index, grant) in grants.withIndex()) {
                appendLine("\nGrant ${index + 1}")
                appendLine("Credential: ${id(grant, "credential_id")}")
                appendLine("Approver ID: ${id(grant, "approver")}")
                appendLine("Target ID: ${id(grant, "target")}")
                appendLine(scope(field(grant, "scope")))
            }
            append("Approve only the exact permissions listed. Decline if any permission is unexpected.")
        }
    }
}
