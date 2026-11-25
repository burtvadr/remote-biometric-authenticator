package io.github.burtvadr.rba.protocol

import io.github.burtvadr.rba.protocol.Cbor.Value

/** Policy snapshots are separate from the immutable enrollment receipt. No
 * authentication challenge can advance a revision. Only an exact decision
 * followed by a receipt on its owning authenticated channel can install one. */
class V2PolicySync(private val current:Snapshot, session:ByteArray, private val deadline:Long) {
    private val session=id(session)
    private var offered:Snapshot?=null
    private var accepted=false
    private var terminal=false
    private fun live(now:Long){valid(!terminal&&now>=0&&now<deadline)}
    private inline fun <T> transition(block:()->T):T=try{block()}catch(e:Exception){terminal=true;throw e}
    fun offer(message:V2Message.Message,now:Long):ByteArray=transition {
        live(now);valid(offered==null&&message.kind==V2Message.Kind.POLICYOFFER)
        val p=message.payload();valid(field(p,"session_id")==session)
        val core=Cbor.ofMap("revision" to field(p,"revision"),"grants" to field(p,"grants"))
        val grants=field(core,"grants") as? Value.Arr?:throw V2Wire.Invalid()
        val owner=current.owner()?:grants.items.firstOrNull()?.let{raw(field(it,"approver"))}
        // Preserve local denials for grants that already existed. New grants
        // are included only after the user explicitly consents to the exact
        // offered snapshot. Removed grants cannot persist in the allow-list.
        val old=current.grants();val allowed=current.local()
        val local=Value.Arr(grants.items.filter{it !in old.items || it in allowed.items})
        val next=Snapshot.create(current.host(),current.credential(),owner,core,local)
        valid(field(p,"digest")==Value.Bytes(next.digest()) && next.revision>=current.revision)
        valid(next.revision!=current.revision || next.digest().contentEquals(current.digest()))
        offered=next;next.digest()
    }
    fun decision(consent:ByteArray?,now:Long):V2Message.Message=transition {
        live(now);valid(!accepted);val next=offered?:throw V2Wire.Invalid()
        if(consent!=null)valid(consent.contentEquals(next.digest()))
        accepted=consent!=null
        if(!accepted)terminal=true
        V2Message.Message.create(V2Message.Kind.POLICYDECISION,Cbor.ofMap("session_id" to session,"revision" to Cbor.uint(next.revision),"digest" to Cbor.bytes(next.digest()),"accepted" to Cbor.uint(if(accepted)1 else 0)))
    }
    /** Store callback must perform a durable compare-and-set. A failure leaves
     * no accepted in-memory policy; re-offer on a new authenticated channel. */
    fun receipt(message:V2Message.Message,now:Long,commit:(ByteArray,ByteArray)->Unit)=transition {
        live(now);terminal=true;valid(accepted&&message.kind==V2Message.Kind.POLICYRECEIPT)
        val next=offered?:throw V2Wire.Invalid();val p=message.payload()
        valid(field(p,"session_id")==session&&field(p,"revision")==Cbor.uint(next.revision)&&field(p,"digest")==Value.Bytes(next.digest()))
        commit(current.encode(),next.encode())
    }
    fun cancel(){terminal=true;offered=null}
    class Snapshot private constructor(private val canonical:ByteArray) {
        private fun record()=V2Wire.decodePayload(canonical)
        private fun core()=field(record(),"core")
        fun host()=raw(field(record(),"host")).copyOf()
        fun credential()=raw(field(record(),"credential")).copyOf()
        fun owner():ByteArray?=raw(field(record(),"owner")).takeIf{b->b.any{it!=0.toByte()}}?.copyOf()
        fun grants()=field(core(),"grants") as Value.Arr
        fun local()=field(record(),"local") as Value.Arr
        val revision:Long get()=(field(core(),"revision") as Value.Uint).value
        fun digest()=V2Message.hash(V2Message.Domain.POLICY,core())
        fun encode()=canonical.copyOf()
        fun policy():V2DevicePolicy?=owner()?.let{V2DevicePolicy.fromCommitted(host(),credential(),it,core(),digest(),local())}
        companion object {
            fun create(host:ByteArray,credential:ByteArray,owner:ByteArray?,core:Value,local:Value.Arr):Snapshot {
                id(host);id(credential);owner?.let{ id(it) }
                val frozen=V2Wire.decodePayload(V2Wire.encodePayload(core));val digest=V2Message.hash(V2Message.Domain.POLICY,frozen)
                valid((field(frozen,"revision") as? Value.Uint)?.value?.let{it>0}==true)
                val grants=field(frozen,"grants") as? Value.Arr?:throw V2Wire.Invalid()
                valid(local.items.all{it in grants.items})
                if(owner==null)valid(grants.items.isEmpty()&&local.items.isEmpty())
                else V2DevicePolicy.fromCommitted(host,credential,owner,frozen,digest,local)
                return Snapshot(V2Wire.encodePayload(Cbor.ofMap("host" to Cbor.bytes(host),"credential" to Cbor.bytes(credential),"owner" to Cbor.bytes(owner?:ByteArray(16)),"core" to frozen,"local" to local)))
            }
            fun decode(encoded:ByteArray):Snapshot {
                val v=V2Wire.decodePayload(encoded);valid(v.entries.size==5)
                val owner=raw(field(v,"owner"));valid(owner.size==16)
                val result=create(raw(field(v,"host")),raw(field(v,"credential")),owner.takeIf{b->b.any{it!=0.toByte()}},field(v,"core"),field(v,"local") as? Value.Arr?:throw V2Wire.Invalid())
                valid(result.encode().contentEquals(encoded));return result
            }
        }
    }
    companion object {
        private fun valid(ok:Boolean){if(!ok)throw V2Wire.Invalid()}
        private fun field(v:Value,k:String)=(v as? Value.Map)?.get(k)?:throw V2Wire.Invalid()
        private fun raw(v:Value)=(v as? Value.Bytes)?.value?:throw V2Wire.Invalid()
        private fun id(v:ByteArray):Value.Bytes{valid(v.size==16&&v.any{it!=0.toByte()});return Value.Bytes(v.copyOf())}
    }
}
