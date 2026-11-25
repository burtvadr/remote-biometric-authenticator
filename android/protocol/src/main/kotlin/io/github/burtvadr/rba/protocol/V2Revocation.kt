package io.github.burtvadr.rba.protocol

/** One enrolled mTLS/HELLO session and one request. Call only after durable
 * local denial. Retry requires a new session, never a reset of this object. */
class V2Revocation(
    record:V2Enrollment.Pending, peerHost:ByteArray, peerKey:ByteArray,
    localCredential:ByteArray, localKey:ByteArray, session:ByteArray,
    private val startedWall:Long, private val startedMono:Long
) {
    private val sid=session.copyOf()
    private val cid=record.credentialId()
    private val token=record.revocationToken()
    private var sent=false
    private var finished=false
    init {
        valid(peerHost.contentEquals(record.hostId())&&peerKey.contentEquals(record.hostKey())&&localCredential.contentEquals(cid)&&localKey.contentEquals(record.transportKey()))
        valid(sid.size==16&&sid.any{it!=0.toByte()}&&startedWall>=record.createdAt()&&startedWall<=Long.MAX_VALUE-60&&startedMono>=0&&startedMono<=Long.MAX_VALUE-60000)
    }
    private fun valid(ok:Boolean){if(!ok)throw V2Wire.Invalid()}
    fun deadline()=startedMono+60000L
    private fun live(now:Long,mono:Long)=now>=startedWall&&now<startedWall+60&&mono>=startedMono&&mono<deadline()
    @Synchronized fun request(now:Long,mono:Long):V2Message.Message {
        try{
            valid(!sent&&!finished&&live(now,mono));sent=true
            return V2Message.Message.create(V2Message.Kind.REVOKE,Cbor.ofMap("session_id" to Cbor.bytes(sid),"credential_id" to Cbor.bytes(cid),"token" to Cbor.bytes(token)))
        }catch(e:Exception){finished=true;throw e}finally{token.fill(0)}
    }
    @Synchronized fun receipt(message:V2Message.Message,now:Long,mono:Long,commit:()->Unit){
        val allowed=sent&&!finished;finished=true;token.fill(0)
        valid(allowed&&live(now,mono)&&message.kind==V2Message.Kind.REVOKERECEIPT)
        val payload=message.payload()
        valid(payload["session_id"]==Cbor.bytes(sid)&&payload["credential_id"]==Cbor.bytes(cid))
        commit()
    }
    @Synchronized fun cancel(){finished=true;token.fill(0)}
}
