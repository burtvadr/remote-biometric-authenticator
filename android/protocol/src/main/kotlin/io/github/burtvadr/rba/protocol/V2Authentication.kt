package io.github.burtvadr.rba.protocol

import io.github.burtvadr.rba.protocol.Cbor.Value

/** Single-channel authentication state machine. Construct only after verified
 * mTLS and HELLO; all binding values must come from that channel and the
 * committed enrollment. The Android adapter must serialize these operations
 * on one owner, use elapsedRealtime, invalidate on disconnect/policy change,
 * and use a fresh strong biometric CryptoObject for the exact returned bytes.
 * This class never treats a UI callback or a transport signature as approval.
 */
class V2Authentication(hostId: ByteArray, credentialId: ByteArray, sessionId: ByteArray,
                       hostNonce: ByteArray, deviceNonce: ByteArray, channel: ByteArray,
                       hostKey: ByteArray, biometricKey: ByteArray) {
    private val host = id(hostId); private val credential = id(credentialId); private val session = id(sessionId)
    private val hn = binding(hostNonce); private val dn = binding(deviceNonce); private val cb = binding(channel)
    private val hk = hostKey.copyOf(); private val bk = biometricKey.copyOf()
    init { requireValid(hk.size == 65 && bk.size == 65 && !hk.contentEquals(bk)) }
    private enum class Stage { REQUEST, NUMBER, MATCH, BIOMETRIC, RESULT, TERMINAL }
    private var stage = Stage.REQUEST
    private var request: V2Message.Message? = null
    private var response: Value.Map? = null
    private var digest: ByteArray? = null
    private var expiry = 0L; private var deadline = 0L
    private var lastWall = -1L; private var lastMono = -1L
    /** Deadline established by the first validated message; never recomputed. */
    @Synchronized fun operationDeadline():Long {
        requireValid(stage!=Stage.REQUEST && stage!=Stage.TERMINAL);return deadline
    }
    private fun clocks(now:Long, mono:Long) {
        requireValid(now >= 0 && mono >= 0 && now >= lastWall && mono >= lastMono)
        lastWall=now; lastMono=mono
        if (stage != Stage.REQUEST) requireValid(now < expiry && mono < deadline)
    }
    private inline fun <T> transition(expected:Stage, now:Long, mono:Long, block:()->T):T {
        try { requireValid(stage==expected); clocks(now,mono); return block() }
        catch (e:Exception) { invalidate(); throw e }
    }
    private fun core():Value.Map = field(request?.payload() ?: throw V2Wire.Invalid(),"core") as? Value.Map ?: throw V2Wire.Invalid()
    private fun checkPolicy(policy:V2DevicePolicy) {
        requireValid(policy.permitsRequest(request ?: throw V2Wire.Invalid()) && digest?.contentEquals(policy.digest())==true)
    }
    private fun base():Array<Pair<String,Value>> = arrayOf("v" to Cbor.uint(2),"session_id" to session,"request_id" to field(core(),"request_id"),"channel" to cb)
    /** Only this method can create a number-entry UI. Returned values are a
     * fresh immutable-by-ownership copy of the validated signed request. */
    @Synchronized fun acceptRequest(msg:V2Message.Message, policy:V2DevicePolicy, now:Long, mono:Long):Value.Map = transition(Stage.REQUEST,now,mono) {
        requireValid(msg.kind==V2Message.Kind.AUTHREQUEST)
        val p=msg.payload(); val c=field(p,"core") as Value.Map
        for ((name,expected) in listOf("host_id" to host,"credential_id" to credential,"session_id" to session,"host_nonce" to hn,"device_nonce" to dn,"channel" to cb))
            requireValid(field(c,name)==expected)
        V2Message.verify(V2Message.Domain.AUTHREQUEST,c,hk,bytes(field(p,"signature")))
        requireValid(policy.permitsRequest(msg))
        val issued=uint(field(c,"issued_at")); val expires=uint(field(c,"expires_at"))
        requireValid(expires>issued && expires-issued<=60 && now<expires && (issued<=now || issued-now<=5))
        val remaining=minOf(60L,expires-now)
        requireValid(mono<=Long.MAX_VALUE-remaining*1000)
        expiry=expires; deadline=mono+remaining*1000
        request=msg; digest=policy.digest(); stage=Stage.NUMBER
        core()
    }
    /** The caller obtains digits only through the manual number-entry UI. */
    @Synchronized fun enterNumber(digits:String, policy:V2DevicePolicy, now:Long, mono:Long):V2Message.Message = transition(Stage.NUMBER,now,mono) {
        checkPolicy(policy)
        val msg=V2Message.Message.create(V2Message.Kind.NUMBERENTRY,Cbor.ofMap("session_id" to session,"request_id" to field(core(),"request_id"),"digits" to Cbor.text(digits)))
        stage=Stage.MATCH; msg
    }
    /** Verify the signed match before making any biometric transcript available.
     * The adapter binds this exact byte sequence to one fresh CryptoObject. */
    @Synchronized fun acceptMatch(msg:V2Message.Message, policy:V2DevicePolicy, now:Long, mono:Long):ByteArray = transition(Stage.MATCH,now,mono) {
        checkPolicy(policy); requireValid(msg.kind==V2Message.Kind.MATCHED)
        val reqHash=Cbor.bytes(V2Message.hash(V2Message.Domain.AUTHREQUEST,core()))
        val expected=Cbor.ofMap(*base(),"request_hash" to reqHash,"matched" to Cbor.uint(1))
        val p=msg.payload(); val actual=field(p,"core")
        requireValid(actual==expected)
        V2Message.verify(V2Message.Domain.MATCHED,actual,hk,bytes(field(p,"signature")))
        val c=Cbor.ofMap(*base(),"request_hash" to reqHash,"match_hash" to Cbor.bytes(V2Message.hash(V2Message.Domain.MATCHED,actual)),"credential_id" to credential,"decision" to Cbor.uint(1))
        response=c; stage=Stage.BIOMETRIC
        V2Message.transcript(V2Message.Domain.AUTHRESPONSE,c)
    }
    /** A raw signature from the per-use biometric adapter, never a UI boolean.
     * It must verify against the enrolled biometric key and owned transcript. */
    @Synchronized fun completeBiometric(signature:ByteArray, policy:V2DevicePolicy, now:Long, mono:Long):V2Message.Message = transition(Stage.BIOMETRIC,now,mono) {
        checkPolicy(policy); val c=response ?: throw V2Wire.Invalid()
        val sig=signature.copyOf()
        V2Message.verify(V2Message.Domain.AUTHRESPONSE,c,bk,sig)
        val msg=V2Message.Message.create(V2Message.Kind.AUTHRESPONSE,Cbor.ofMap("core" to c,"signature" to Cbor.bytes(sig)))
        stage=Stage.RESULT; response=null; msg
    }
    /** Informational result only: never confers authentication rights. */
    @Synchronized fun acceptResult(msg:V2Message.Message, now:Long, mono:Long):Boolean = transition(Stage.RESULT,now,mono) {
        requireValid(msg.kind==V2Message.Kind.AUTHRESULT)
        val p=msg.payload(); requireValid(field(p,"session_id")==session && field(p,"request_id")==field(core(),"request_id"))
        val ok=uint(field(p,"outcome"))==1L; invalidate(); ok
    }
    @Synchronized fun cancel():V2Message.Message? {
        val c=request?.let { core() }
        invalidate()
        return c?.let { V2Message.Message.create(V2Message.Kind.CANCEL,Cbor.ofMap("session_id" to session,"request_id" to field(it,"request_id"))) }
    }
    @Synchronized fun invalidate() { stage=Stage.TERMINAL; request=null; response=null; digest=null }
    companion object {
        private fun requireValid(ok:Boolean) { if(!ok) throw V2Wire.Invalid() }
        private fun field(v:Value,k:String):Value=(v as? Value.Map)?.get(k) ?: throw V2Wire.Invalid()
        private fun id(v:ByteArray):Value.Bytes { requireValid(v.size==16 && v.any{it!=0.toByte()});return Cbor.bytes(v.copyOf()) as Value.Bytes }
        private fun binding(v:ByteArray):Value.Bytes { requireValid(v.size==32);return Cbor.bytes(v.copyOf()) as Value.Bytes }
        private fun bytes(v:Value):ByteArray=(v as? Value.Bytes)?.value ?: throw V2Wire.Invalid()
        private fun uint(v:Value):Long { val n=(v as? Value.Uint)?.value ?: throw V2Wire.Invalid();requireValid(n>=0);return n }
    }
}
