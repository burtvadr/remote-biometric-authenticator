package io.github.burtvadr.rba.protocol

import java.io.File
import java.io.ByteArrayInputStream
import io.github.burtvadr.rba.protocol.Cbor.Value

/** Reuses independently generated B.2.1 wire/transcript fixtures. Tests pure
 * policy intersection; no mocked result is accepted as biometric evidence. */
object V2DevicePolicyTests {
    private fun bytes(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun id(n:Int)=ByteArray(16){n.toByte()}
    private fun replace(v:Value.Map,name:String,value:Value)=Value.Map(v.entries.map { (k,x) -> k to if(k==Value.Text(name)) value else x })
    fun run(dir:File):Int {
        val lines=File(dir,"v2-message.tsv").readLines().filterNot{it.startsWith('#')}.associate { val f=it.split('\t'); f[0] to f }
        fun fixture(name:String)=V2Message.Message.read(ByteArrayInputStream(bytes(lines.getValue(name)[2])))
        val request=fixture("msg-12"); val offer=fixture("msg-20"); val op=offer.payload()
        val core=Cbor.ofMap("revision" to op["revision"]!!,"grants" to op["grants"]!!)
        val digest=(op["digest"] as Value.Bytes).value
        val grants=op["grants"] as Value.Arr
        val grant=grants.items.single() as Value.Map
        var count=0
        fun ck(ok:Boolean) { check(ok){"device policy check ${count+1}"}; count++ }
        fun policy(local:Value.Arr=grants, host:ByteArray=id(3), c:Value=core, d:ByteArray=digest)=V2DevicePolicy.fromCommitted(host,id(4),id(6),c,d,local)
        fun invalid(f:()->Unit)=runCatching(f).exceptionOrNull() is V2Wire.Invalid
        fun req(name:String,v:Value):V2Message.Message {
            val p=request.payload(); return V2Message.Message.create(V2Message.Kind.AUTHREQUEST,replace(p,"core",replace(p["core"] as Value.Map,name,v)))
        }
        fun next(revision:Long, g:Value.Arr=grants):V2Message.Message {
            val c=Cbor.ofMap("revision" to Cbor.uint(revision),"grants" to g)
            return V2Message.Message.create(V2Message.Kind.POLICYOFFER,Cbor.ofMap("session_id" to op["session_id"]!!,"revision" to Cbor.uint(revision),"grants" to g,"digest" to Cbor.bytes(V2Message.hash(V2Message.Domain.POLICY,c))))
        }
        val p=policy()
        ck(p.permitsRequest(request))
        ck(!policy(Value.Arr(emptyList())).permitsRequest(request))
        ck(!policy(host=id(8)).permitsRequest(request))
        for(name in listOf("credential_id","approver","target","host_id")) ck(!p.permitsRequest(req(name,Cbor.bytes(id(99)))))
        ck(!p.permitsRequest(req("policy_revision",Cbor.uint(0))))
        ck(!p.permitsRequest(req("policy_revision",Cbor.uint(2))))
        ck(!p.permitsRequest(req("scope",Cbor.ofMap("purpose" to Cbor.text("authenticate"),"service" to Cbor.text("sudo"),"operation" to Cbor.text("service-auth")))))
        ck(!p.permitsRequest(offer))
        ck(invalid{policy(d=ByteArray(32))})
        ck(invalid{policy(Value.Arr(listOf(replace(grant,"credential_id",Cbor.bytes(id(99))))))})
        ck(invalid{policy(Value.Arr(listOf(replace(grant,"approver",Cbor.bytes(id(99))))))})
        ck(p.compareOffer(offer)==V2DevicePolicy.Offer.SAME)
        ck(p.compareOffer(next(0))==V2DevicePolicy.Offer.REJECT)
        ck(p.compareOffer(next(1,Value.Arr(emptyList())))==V2DevicePolicy.Offer.REJECT)
        ck(p.compareOffer(next(2))==V2DevicePolicy.Offer.ADVANCE)
        ck(p.compareOffer(next(2,Value.Arr(listOf(replace(grant,"credential_id",Cbor.bytes(id(99)))))))==V2DevicePolicy.Offer.REJECT)
        ck(p.compareOffer(request)==V2DevicePolicy.Offer.REJECT)
        // A prospective offer has no effect on the durable policy.
        ck(p.revision==1L && p.permitsRequest(request) && !p.permitsRequest(req("policy_revision",Cbor.uint(2))))
        val sid=(op["session_id"] as Value.Bytes).value
        val snap=V2PolicySync.Snapshot.create(id(3),id(4),id(6),core,grants)
        val noLocal=V2PolicySync.Snapshot.create(id(3),id(4),id(6),core,Value.Arr(emptyList()))
        fun receipt(o:V2Message.Message):V2Message.Message {val v=o.payload();return V2Message.Message.create(V2Message.Kind.POLICYRECEIPT,Cbor.ofMap("session_id" to v["session_id"]!!,"revision" to v["revision"]!!,"digest" to v["digest"]!!))}
        val o2=next(2);val r2=receipt(o2)
        val sync=V2PolicySync(snap,sid,100)
        val consent=sync.offer(o2,1)
        ck(sync.decision(consent,2).payload()["accepted"]==Cbor.uint(1))
        var updated:V2PolicySync.Snapshot?=null
        sync.receipt(r2,3){old,new->check(old.contentEquals(snap.encode()));updated=V2PolicySync.Snapshot.decode(new)}
        ck(updated?.revision==2L)
        ck(invalid{sync.receipt(r2,4){_,_->error("replay")}})
        ck(snap.revision==1L)
        val decline=V2PolicySync(snap,sid,100);decline.offer(o2,1)
        ck(decline.decision(null,2).payload()["accepted"]==Cbor.uint(0))
        ck(invalid{decline.receipt(r2,3){_,_->error("declined")}})
        val bad=V2PolicySync(snap,sid,100);bad.offer(o2,1)
        ck(invalid{bad.decision(ByteArray(32),2)})
        val late=V2PolicySync(snap,sid,100);late.offer(o2,1)
        ck(invalid{late.decision(consent,100)})
        ck(invalid{V2PolicySync(snap,id(99),100).offer(o2,1)})
        ck(invalid{V2PolicySync(updated!!,sid,100).offer(next(1),1)})
        ck(invalid{V2PolicySync(snap,sid,100).offer(next(1,Value.Arr(emptyList())),1)})
        val lost=V2PolicySync(snap,sid,100);lost.offer(o2,1);lost.decision(consent,2);lost.cancel()
        ck(snap.revision==1L)
        val recover=V2PolicySync(snap,sid,100);recover.decision(recover.offer(o2,1),2);recover.receipt(r2,3){_,n->ck(n.contentEquals(updated!!.encode()))}
        val preserve=V2PolicySync(noLocal,sid,100);preserve.decision(preserve.offer(o2,1),2);preserve.receipt(r2,3){_,n->ck(V2PolicySync.Snapshot.decode(n).local().items.isEmpty())}
        val empty=next(2,Value.Arr(emptyList()));val remove=V2PolicySync(snap,sid,100)
        remove.decision(remove.offer(empty,1),2);remove.receipt(receipt(empty),3){_,n->val v=V2PolicySync.Snapshot.decode(n);ck(v.grants().items.isEmpty()&&v.owner()!!.contentEquals(id(6)))}
        val fail=V2PolicySync(snap,sid,100);fail.decision(fail.offer(o2,1),2)
        ck(runCatching{fail.receipt(r2,3){_,_->error("disk failure")}}.isFailure)
        ck(invalid{fail.receipt(r2,4){_,_->error("replay")}})
        val host=id(3); val mutableGrant=op["grants"] as Value.Arr
        val frozen=policy(local=mutableGrant,host=host)
        host.fill(0); (grant["target"] as Value.Bytes).value.fill(0); frozen.digest().fill(0)
        ck(frozen.permitsRequest(request))
        return count
    }
}
