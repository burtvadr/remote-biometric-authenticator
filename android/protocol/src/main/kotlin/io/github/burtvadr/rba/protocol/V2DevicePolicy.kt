package io.github.burtvadr.rba.protocol

import io.github.burtvadr.rba.protocol.Cbor.Value

/** Immutable intersection of a durably committed host policy and explicitly
 * permitted device grants. Never constructs a policy from AUTH_REQUEST.
 *
 * The Android enrollment/policy state machine must authenticate the binding,
 * verify consent and receipt, and durably commit the policy before loading it
 * here. This class does not perform those transitions or establish hardware
 * trust. A positive policy check is not a biometric approval.
 */
class V2DevicePolicy private constructor(
    private val hostId: Value.Bytes,
    private val credentialId: Value.Bytes,
    private val approver: Value.Bytes,
    val revision: Long,
    private val policyDigest: ByteArray,
    private val grants: Set<Value.Bytes>,
    private val localGrants: Set<Value.Bytes>,
) {
    enum class Offer { SAME, ADVANCE, REJECT }
    fun digest(): ByteArray = policyDigest.copyOf()

    /** Pure check; never mutates or accepts a policy. An advance must go through
     * the separate authenticated offer/consent/receipt state machine. */
    fun compareOffer(offer: V2Message.Message): Offer {
        if (offer.kind != V2Message.Kind.POLICYOFFER) return Offer.REJECT
        return try {
            val p = offer.payload()
            val next = positiveRevision(field(p,"revision"))
            // Validate even a newer policy against the exact enrolled binding.
            grantSet(field(p,"grants"),credentialId,approver)
            when {
                next < revision -> Offer.REJECT
                next == revision && field(p,"digest") == Value.Bytes(policyDigest) -> Offer.SAME
                next == revision -> Offer.REJECT
                else -> Offer.ADVANCE
            }
        } catch (_: V2Wire.Invalid) { Offer.REJECT }
    }

    /** Caller must separately verify the host signature, channel/nonces,
     * freshness and session state before presenting a number prompt. */
    fun permitsRequest(request: V2Message.Message): Boolean {
        if (request.kind != V2Message.Kind.AUTHREQUEST) return false
        return try {
            val core = field(request.payload(),"core")
            if (field(core,"host_id") != hostId || field(core,"credential_id") != credentialId ||
                field(core,"approver") != approver || positiveRevision(field(core,"policy_revision")) != revision) return false
            val key = grantKey(Cbor.ofMap(
                "credential_id" to credentialId, "approver" to approver,
                "target" to field(core,"target"), "scope" to field(core,"scope")))
            key in grants && key in localGrants
        } catch (_: V2Wire.Invalid) { false }
    }

    companion object {
        private fun requireValid(ok: Boolean) { if (!ok) throw V2Wire.Invalid() }
        private fun field(v: Value, k: String): Value = (v as? Value.Map)?.get(k) ?: throw V2Wire.Invalid()
        private fun id(raw: ByteArray): Value.Bytes {
            requireValid(raw.size==16 && raw.any { it != 0.toByte() }); return Value.Bytes(raw.copyOf())
        }
        // Host SQLite revision is positive signed 64-bit; reject values the
        // authoritative host can never generate rather than narrowing them.
        private fun positiveRevision(v: Value): Long {
            val n=(v as? Value.Uint)?.value ?: throw V2Wire.Invalid()
            requireValid(n>0); return n
        }
        private fun grantKey(v: Value): Value.Bytes = Value.Bytes(V2Wire.encodePayload(v))
        private fun grantSet(v: Value, credential: Value.Bytes, owner: Value.Bytes): Set<Value.Bytes> {
            // Use the normative grant schema/order validation, not another codec.
            val snap=V2Wire.decodePayload(V2Wire.encodePayload(Cbor.ofMap("revision" to Cbor.uint(1),"grants" to v)))
            V2Message.hash(V2Message.Domain.POLICY,snap)
            val arr=field(snap,"grants") as? Value.Arr ?: throw V2Wire.Invalid()
            return arr.items.map { g ->
                requireValid(field(g,"credential_id")==credential && field(g,"approver")==owner)
                grantKey(g)
            }.toSet()
        }
        /** Load only durable, committed records from the trusted application
         * store. An empty local allow-list is deny-all, never allow-all. */
        fun fromCommitted(hostId: ByteArray, credentialId: ByteArray, owner: ByteArray,
                          policyCore: Value, expectedDigest: ByteArray, localAllowed: Value.Arr): V2DevicePolicy {
            val host=id(hostId); val credential=id(credentialId); val approver=id(owner)
            val snap=V2Wire.decodePayload(V2Wire.encodePayload(policyCore))
            val digest=V2Message.hash(V2Message.Domain.POLICY,snap)
            requireValid(expectedDigest.size==32 && expectedDigest.contentEquals(digest))
            val revision=positiveRevision(field(snap,"revision"))
            val grants=grantSet(field(snap,"grants"),credential,approver)
            val local=grantSet(localAllowed,credential,approver)
            return V2DevicePolicy(host,credential,approver,revision,digest,grants,local)
        }
    }
}
