package io.github.burtvadr.rba.protocol

import io.github.burtvadr.rba.protocol.Cbor.Value
import java.security.MessageDigest

/** Enrollment-only state machine. The application must supply the actual
 * provisional TLS handshake facts and generate fresh non-exportable keys with
 * the returned role challenges. No production trust is installed here until
 * the durable store confirms activation. All methods use one serialized owner.
 */
class V2Enrollment(channel: ByteArray, hostCert: ByteArray, clientCert: ByteArray,
                   hostKey: ByteArray, provisionalKey: ByteArray, private val pake:Pake) : AutoCloseable {
    interface Exchange:AutoCloseable {
        val share:ByteArray
        fun confirm(hostShare:ByteArray,hostTag:ByteArray):ByteArray
    }
    /** Production implementation uses the existing native SPAKE2 library.
     * No shared key material is exposed to this state machine. */
    interface Pake {
        fun generateCode():ByteArray
        fun start(code:ByteArray,host:ByteArray,credential:ByteArray,aad:ByteArray):Exchange
    }
    /** Implement with one durable transaction per operation. Compare the
     * entire expected pending record before activation; no activation on an
     * exception, no implicit replacement of active credentials. No mock
     * implementation in production. The pending record itself is not a grant.
     */
    interface PendingStore {
        fun stage(record:ByteArray)
        fun activate(expectedPending:ByteArray)
    }
    class Challenges(val transport:ByteArray,val biometric:ByteArray)
    class Share(val message:V2Message.Message,val displayCode:ByteArray?)
    class Confirmation(val message:V2Message.Message,val contextHash:ByteArray,
                       val hostCert:ByteArray,val provisionalCert:ByteArray,
                       val hostKeyHash:ByteArray,val provisionalKeyHash:ByteArray,
                       val transportKeyHash:ByteArray,val biometricKeyHash:ByteArray)
    class Proofs(val transport:ByteArray,val biometric:ByteArray)
    private enum class Stage { START, SHARE, CONFIRM, CONSENT, PROOFS, OFFER, STAGE, RECEIPT, TERMINAL }
    private var stage=Stage.START
    private val cb=bytes32(channel);private val hc=bytes32(hostCert);private val pc=bytes32(clientCert)
    private val hk=point(hostKey);private val pk=point(provisionalKey)
    init { valid(hk!=pk) }
    private var start:V2Message.Message?=null
    private var context:Value.Map?=null
    private var exchange:Exchange?=null
    private var pending:Pending?=null
    private var expiry=0L;private var deadline=0L;private var lastWall=-1L;private var lastMono=-1L
    /** Deadline established by the first validated message; never recomputed. */
    @Synchronized fun operationDeadline():Long {
        valid(stage!=Stage.START && stage!=Stage.TERMINAL);return deadline
    }
    private fun clocks(now:Long,mono:Long){
        valid(now>=0 && mono>=0 && now>=lastWall && mono>=lastMono)
        lastWall=now;lastMono=mono
        if(stage!=Stage.START)valid(now<expiry && mono<deadline)
    }
    private inline fun <T> step(expected:Stage,now:Long,mono:Long,block:()->T):T {
        try{valid(stage==expected);clocks(now,mono);return block()}
        catch(e:Exception){close();throw e}
    }
    private fun s(k:String)=field(start?.payload()?:throw V2Wire.Invalid(),k)
    private fun c(k:String)=field(context?:throw V2Wire.Invalid(),k)
    private fun base()=arrayOf("v" to Cbor.uint(2),"enrollment_id" to s("enrollment_id"),"host_id" to s("host_id"),"nonce" to s("nonce"),"channel" to cb)
    private fun proof(role:Int)=Cbor.ofMap(*base(),"credential_id" to c("credential_id"),"transport_key" to c("transport_key"),"biometric_key" to c("biometric_key"),"role" to Cbor.uint(role))
    private fun msg(k:V2Message.Kind,vararg fields:Pair<String,Value>)=V2Message.Message.create(k,Cbor.ofMap(*fields))
    private fun exact(m:V2Message.Message,k:V2Message.Kind):Value.Map{
        valid(m.kind==k);val p=m.payload();valid(field(p,"enrollment_id")==s("enrollment_id"));return p
    }
    /** Does not grant trust; adapter generates fresh keys for both challenges. */
    @Synchronized fun acceptStart(m:V2Message.Message,now:Long,mono:Long):Challenges=step(Stage.START,now,mono){
        valid(m.kind==V2Message.Kind.ENROLLSTART);start=m
        id(raw(s("enrollment_id")));id(raw(s("host_id")))
        expiry=uint(s("expires_at"));valid(expiry>now && expiry-now<=120)
        val remain=(expiry-now)*1000;valid(mono<=Long.MAX_VALUE-remain);deadline=mono+remain
        val a=V2Message.hash(V2Message.Domain.ATTEST,Cbor.ofMap(*base(),"role" to Cbor.uint(0)))
        val b=V2Message.hash(V2Message.Domain.ATTEST,Cbor.ofMap(*base(),"role" to Cbor.uint(1)))
        stage=Stage.SHARE;Challenges(a,b)
    }
    /** DeviceTypes: code entered by user. HostTypes: device generates and
     * returns local display code; it never travels in a wire message. */
    @Synchronized fun share(credential:ByteArray,transportKey:ByteArray,biometricKey:ByteArray,entered:ByteArray?,now:Long,mono:Long):Share {
        var secret:ByteArray?=null
        try{return step(Stage.SHARE,now,mono){
            val cid=id(credential);val tk=point(transportKey);val bk=point(biometricKey)
            valid(setOf(hk,pk,tk,bk).size==4)
            val direction=uint(s("direction"));valid((direction==0L)==(entered!=null))
            val code=entered?.copyOf()?:pake.generateCode();secret=code
            valid(code.size==6 && code.all{it.toInt() in 48..57})
            val ctx=Cbor.ofMap(*base(),"credential_id" to cid,"expires_at" to s("expires_at"),"direction" to s("direction"),"suite" to s("suite"),"host_cert" to hc,"provisional_client_cert" to pc,"host_key" to hk,"provisional_client_key" to pk,"transport_key" to tk,"biometric_key" to bk)
            val aad=V2Message.transcript(V2Message.Domain.ENROLLCONTEXT,ctx)
            val display=if(direction==1L)code.copyOf() else null
            try{
                val ex=pake.start(code,raw(s("host_id")).copyOf(),raw(cid).copyOf(),aad);exchange=ex
                val m=msg(V2Message.Kind.ENROLLSHARE,"enrollment_id" to s("enrollment_id"),"credential_id" to cid,"transport_key" to tk,"biometric_key" to bk,"share" to point(ex.share))
                context=ctx;stage=Stage.CONFIRM;Share(m,display)
            }catch(e:Exception){display?.fill(0);throw e}
        }}finally{secret?.fill(0);entered?.fill(0)}
    }
    /** The native exchange verifies A before releasing B. UI must display
     * these actual fingerprint values and ask for explicit local consent. */
    @Synchronized fun confirm(m:V2Message.Message,now:Long,mono:Long):Confirmation=step(Stage.CONFIRM,now,mono){
        val p=exact(m,V2Message.Kind.ENROLLCONFIRMA)
        val ex=exchange?:throw V2Wire.Invalid();exchange=null
        val tag=try{ex.confirm(raw(field(p,"share")),raw(field(p,"confirmation")))}finally{ex.close()}
        val reply=msg(V2Message.Kind.ENROLLCONFIRMB,"enrollment_id" to s("enrollment_id"),"confirmation" to bytes32(tag))
        stage=Stage.CONSENT
        Confirmation(reply,contextHash(),raw(hc).copyOf(),raw(pc).copyOf(),sha(raw(hk)),sha(raw(pk)),sha(raw(c("transport_key"))),sha(raw(c("biometric_key"))))
    }
    private fun contextHash()=V2Message.hash(V2Message.Domain.ENROLLCONTEXT,context?:throw V2Wire.Invalid())
    /** The UI must explicitly approve the displayed context. Bind fresh
     * strong biometric CryptoObject to the exact biometric proof bytes. */
    @Synchronized fun approve(approved:ByteArray,now:Long,mono:Long):Proofs=step(Stage.CONSENT,now,mono){
        valid(MessageDigest.isEqual(approved,contextHash()));stage=Stage.PROOFS
        Proofs(V2Message.transcript(V2Message.Domain.ENROLLKEYPROOF,proof(0)),V2Message.transcript(V2Message.Domain.ENROLLKEYPROOF,proof(1)))
    }
    @Synchronized fun evidence(transportChain:List<ByteArray>,biometricChain:List<ByteArray>,transportProof:ByteArray,biometricProof:ByteArray,cleanupRecords:List<Pending>,now:Long,mono:Long):V2Message.Message=step(Stage.PROOFS,now,mono){
        V2Message.verify(V2Message.Domain.ENROLLKEYPROOF,proof(0),raw(c("transport_key")),transportProof)
        V2Message.verify(V2Message.Domain.ENROLLKEYPROOF,proof(1),raw(c("biometric_key")),biometricProof)
        // No token may leave the device for a different host, even if the
        // user successfully confirmed a fresh PAKE with that other host.
        valid(cleanupRecords.size<=32)
        val ids=cleanupRecords.map{r->
            valid(r.hostId().contentEquals(raw(s("host_id")))&&r.hostKey().contentEquals(raw(hk)))
            valid(!r.credentialId().contentEquals(raw(c("credential_id"))))
            Cbor.bytes(r.credentialId())
        }
        valid(ids.toSet().size==ids.size)
        val cleanupTokens=cleanupRecords.map{it.revocationToken()}
        valid(cleanupTokens.map{Cbor.bytes(it)}.toSet().size==cleanupTokens.size)
        val m=msg(V2Message.Kind.ENROLLEVIDENCE,"enrollment_id" to s("enrollment_id"),"transport_chain" to arr(transportChain),"biometric_chain" to arr(biometricChain),"transport_proof" to Cbor.bytes(transportProof.copyOf()),"biometric_proof" to Cbor.bytes(biometricProof.copyOf()),"cleanup_tokens" to arr(cleanupTokens))
        stage=Stage.OFFER;m
    }
    /** Offer does not install trust. UI must display the exact initial policy
     * and explicitly accept its digest before the pending write. */
    @Synchronized fun acceptOffer(m:V2Message.Message,now:Long,mono:Long):ByteArray=step(Stage.OFFER,now,mono){
        val p=exact(m,V2Message.Kind.ENROLLOFFER);valid(field(p,"credential_id")==c("credential_id"))
        val record=Cbor.ofMap("host_id" to s("host_id"),"host_key" to hk,"host_cert" to hc,"transport_key" to c("transport_key"),"biometric_key" to c("biometric_key"),"offer" to p,"created_at" to Cbor.uint(now),"recover_until" to Cbor.uint(Math.addExact(now,86400L)))
        val saved=Pending.decode(V2Wire.encodePayload(record));pending=saved;stage=Stage.STAGE;saved.offerHash()
    }
    @Synchronized fun stageOffer(approvedOfferHash:ByteArray,store:PendingStore,now:Long,mono:Long):V2Message.Message=step(Stage.STAGE,now,mono){
        val p=pending?:throw V2Wire.Invalid();valid(MessageDigest.isEqual(approvedOfferHash,p.offerHash()))
        val ack=msg(V2Message.Kind.ENROLLSTAGED,"enrollment_id" to s("enrollment_id"),"offer_hash" to bytes32(p.offerHash()))
        store.stage(p.encode());stage=Stage.RECEIPT;ack
    }
    @Synchronized fun receipt(m:V2Message.Message,store:PendingStore,now:Long,mono:Long)=step(Stage.RECEIPT,now,mono){
        val p=pending?:throw V2Wire.Invalid();val payload=exact(m,V2Message.Kind.ENROLLRECEIPT)
        valid(MessageDigest.isEqual(raw(field(payload,"offer_hash")),p.offerHash())&&MessageDigest.isEqual(raw(field(payload,"receipt")),p.receipt()))
        store.activate(p.encode());close()
    }
    /** Disconnection after staging does not erase the durable record; receipt
     * recovery or explicit local re-enrollment is required. */
    @Synchronized override fun close(){val ex=exchange;exchange=null;stage=Stage.TERMINAL;start=null;context=null;pending=null;ex?.close()}
    @Synchronized fun cancel():V2Message.Message?{val m=start?.let{msg(V2Message.Kind.ENROLLCANCEL,"enrollment_id" to field(it.payload(),"enrollment_id"))};close();return m}

    /** Immutable pending record; storage adapter must bind the actual fresh
     * Keystore aliases to the two exact public keys, store privately and bound
     * retention. Never load this record as an active device policy. */
    class Pending private constructor(private val encoded:ByteArray){
        private fun record()=V2Wire.decodePayload(encoded)
        private fun offer()=field(record(),"offer")
        fun encode()=encoded.copyOf()
        fun offerHash()=V2Message.hash(V2Message.Domain.ENROLLOFFER,offer())
        fun receipt()=raw(field(offer(),"receipt")).copyOf()
        internal fun revocationToken()=raw(field(offer(),"token")).copyOf()
        /** Initial grants were explicitly reviewed before durable staging.
         * Empty initial policy is deny-all. Later revisions must use a separate
         * durable policy-consent transaction, never AUTH_REQUEST. */
        fun initialSnapshot():V2PolicySync.Snapshot {
            val o=offer();val grants=field(o,"grants") as Value.Arr
            val core=Cbor.ofMap("revision" to field(o,"revision"),"grants" to grants)
            val owner=grants.items.firstOrNull()?.let{raw(field(it,"approver"))}
            return V2PolicySync.Snapshot.create(hostId(),credentialId(),owner,core,grants)
        }
        fun initialPolicy():V2DevicePolicy?=initialSnapshot().policy()
        fun hostId()=raw(field(record(),"host_id")).copyOf()
        fun hostKey()=raw(field(record(),"host_key")).copyOf()
        fun credentialId()=raw(field(offer(),"credential_id")).copyOf()
        fun enrollmentId()=raw(field(offer(),"enrollment_id")).copyOf()
        fun transportKey()=raw(field(record(),"transport_key")).copyOf()
        fun biometricKey()=raw(field(record(),"biometric_key")).copyOf()
        fun createdAt()=uint(field(record(),"created_at"))
        fun recoverUntil()=uint(field(record(),"recover_until"))
        /** Start only after actual production mTLS and HELLO with the pending
         * host pin and credential; do not dispatch authentication requests. */
        fun recover(peerHostId:ByteArray,peerHostKey:ByteArray,localCredential:ByteArray,localTransportKey:ByteArray,session:ByteArray,now:Long,mono:Long):Recovery {
            valid(peerHostId.contentEquals(hostId())&&peerHostKey.contentEquals(hostKey())&&localCredential.contentEquals(credentialId())&&localTransportKey.contentEquals(transportKey()))
            valid(now>=createdAt() && now<recoverUntil() && mono>=0 && mono<=Long.MAX_VALUE-60000)
            return Recovery(this,id(session),now,mono)
        }
        companion object{
            fun decode(encoded:ByteArray):Pending{
                val copy=encoded.copyOf();val r=V2Wire.decodePayload(copy)
                valid(r.entries.size==8);val created=uint(field(r,"created_at"));val until=uint(field(r,"recover_until"));valid(until>created && until-created==86400L);id(raw(field(r,"host_id")));bytes32(raw(field(r,"host_cert")))
                valid(setOf(point(raw(field(r,"host_key"))),point(raw(field(r,"transport_key"))),point(raw(field(r,"biometric_key")))).size==3)
                val p=field(r,"offer");id(raw(field(p,"enrollment_id")));id(raw(field(p,"credential_id")));V2Message.hash(V2Message.Domain.ENROLLOFFER,p)
                valid(uint(field(p,"revision"))==1L)
                val grants=field(p,"grants") as? Value.Arr?:throw V2Wire.Invalid();valid(grants.items.size<=1)
                for(g in grants.items){valid(field(g,"credential_id")==field(p,"credential_id")&&field(g,"approver")==field(g,"target")&&field(g,"scope")==Cbor.ofMap("purpose" to Cbor.text("authenticate"),"service" to Cbor.text("rba"),"operation" to Cbor.text("authenticate")))}
                valid(raw(field(p,"token")).any{it!=0.toByte()}&&raw(field(p,"receipt")).any{it!=0.toByte()}&&field(p,"token")!=field(p,"receipt"))
                return Pending(copy)
            }
        }
    }
    class Recovery internal constructor(private val pending:Pending,private val session:Value.Bytes,private val startedWall:Long,private val startedMono:Long){
        private var sent=false;private var finished=false
        @Synchronized fun request():V2Message.Message{valid(!sent&&!finished);sent=true;return V2Message.Message.create(V2Message.Kind.ENROLLSTATUS,Cbor.ofMap("session_id" to session,"enrollment_id" to id(pending.enrollmentId()),"receipt" to bytes32(pending.receipt())))}
        @Synchronized fun accept(m:V2Message.Message,store:PendingStore,now:Long,mono:Long){valid(sent&&!finished);finished=true
            valid(now>=startedWall&&now<pending.recoverUntil()&&now-startedWall<60&&mono>=startedMono&&mono-startedMono<60000)
            val p=m.payload();valid(m.kind==V2Message.Kind.ENROLLSTATUSRESULT&&field(p,"session_id")==session&&field(p,"enrollment_id")==id(pending.enrollmentId())&&uint(field(p,"state"))==1L&&MessageDigest.isEqual(raw(field(p,"receipt")),pending.receipt()))
            store.activate(pending.encode())
        }
        @Synchronized fun cancel(){finished=true}
    }
    companion object{
        private fun valid(ok:Boolean){if(!ok)throw V2Wire.Invalid()}
        private fun field(v:Value,k:String):Value=(v as? Value.Map)?.get(k)?:throw V2Wire.Invalid()
        private fun raw(v:Value):ByteArray=(v as? Value.Bytes)?.value?:throw V2Wire.Invalid()
        private fun id(x:ByteArray):Value.Bytes{valid(x.size==16&&x.any{it!=0.toByte()});return Value.Bytes(x.copyOf())}
        private fun bytes32(x:ByteArray):Value.Bytes{valid(x.size==32);return Value.Bytes(x.copyOf())}
        private fun point(x:ByteArray):Value.Bytes{V2Message.publicKey(x);return Value.Bytes(x.copyOf())}
        private fun uint(v:Value):Long{val n=(v as? Value.Uint)?.value?:throw V2Wire.Invalid();valid(n>=0);return n}
        private fun arr(xs:List<ByteArray>)=Value.Arr(xs.map{Value.Bytes(it.copyOf())})
        private fun sha(x:ByteArray)=MessageDigest.getInstance("SHA-256").digest(x)
    }
}
