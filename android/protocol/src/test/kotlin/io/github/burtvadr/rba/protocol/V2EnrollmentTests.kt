package io.github.burtvadr.rba.protocol

import java.io.File
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPrivateKeySpec
import io.github.burtvadr.rba.protocol.Cbor.Value

/** Test-only PAKE boundary and store. These test transition semantics, not
 * cryptographic PAKE or Android hardware/disk. The Rust crate tests real PAKE. */
object V2EnrollmentTests {
    private fun hex(s:String)=s.chunked(2).map{it.toInt(16).toByte()}.toByteArray()
    private fun id(n:Int)=ByteArray(16){n.toByte()}
    private fun b(n:Int)=ByteArray(32){n.toByte()}
    private fun replace(v:Value.Map,k:String,x:Value)=Value.Map(v.entries.map{(key,value)->key to if(key==Value.Text(k)) x else value})
    private class Harness(private val sharePoint:ByteArray,private val expected:ByteArray):V2Enrollment.Pake {
        var closed=false;var started=false;var confirmed=false
        override fun generateCode()="004827".toByteArray()
        override fun start(code:ByteArray,host:ByteArray,credential:ByteArray,aad:ByteArray):V2Enrollment.Exchange {
            check(!started&&code.contentEquals("004827".toByteArray())&&host.contentEquals(id(3))&&credential.contentEquals(id(4))&&aad.contentEquals(expected));started=true
            return object:V2Enrollment.Exchange {
                override val share=sharePoint.copyOf()
                override fun confirm(hostShare:ByteArray,hostTag:ByteArray):ByteArray {if(closed||confirmed||!hostTag.contentEquals(b(10)))throw V2Wire.Invalid();confirmed=true;return b(11)}
                override fun close(){closed=true}
            }
        }
    }
    private class Store:V2Enrollment.PendingStore {
        var saved:ByteArray?=null;var active=false;var failStage=false;var failActivate=false
        override fun stage(record:ByteArray){if(failStage)throw IllegalStateException("test failure");check(saved==null);saved=record.copyOf()}
        override fun activate(expectedPending:ByteArray){if(failActivate)throw IllegalStateException("test failure");check(!active&&saved!!.contentEquals(expectedPending));active=true}
    }
    fun run(dir:File, trace:ByteArray?=null):Int {
        val fixtures=File(dir,"v2-enrollment-context.tsv").readLines().filterNot{it.startsWith('#')}.map{it.split('\t')}
        val rows=File(dir,"v2-message.tsv").readLines().filterNot{it.startsWith('#')}.associate{val f=it.split('\t');f[0] to f}
        fun msg(n:Int)=V2Message.Message.read(ByteArrayInputStream(hex(rows.getValue("msg-$n")[2])))
        fun mutate(m:V2Message.Message,k:String,v:Value)=V2Message.Message.create(m.kind,replace(m.payload(),k,v))
        fun field(m:V2Message.Message,k:String)=m.payload()[k]!!
        fun raw(v:Value)=(v as Value.Bytes).value
        val tk=raw(field(msg(31),"transport_key"));val bk=raw(field(msg(31),"biometric_key"));val hk=raw(field(msg(31),"share"))
        val pk=hex("04e2534a3532d08fbba02dde659ee62bd0031fe2db785596ef509302446b030852e0f1575a4c633cc719dfee5fda862d764efc96c3f30ee0055c42c23f184ed8c6")
        val params=AlgorithmParameters.getInstance("EC").apply{init(ECGenParameterSpec("secp256r1"))}.getParameterSpec(ECParameterSpec::class.java)
        fun sign(bytes:ByteArray,n:Long):ByteArray=Signature.getInstance("SHA256withECDSAinP1363Format").run{initSign(KeyFactory.getInstance("EC").generatePrivate(ECPrivateKeySpec(BigInteger.valueOf(n),params)));update(bytes);sign()}
        fun session(d:Int=0):Pair<V2Enrollment,Harness>{val h=Harness(hk,hex(fixtures[d][1]));return V2Enrollment(b(3),b(8),b(9),hk,pk,h) to h}
        fun start(d:Int)=mutate(msg(30),"direction",Cbor.uint(d))
        val grant=Cbor.ofMap("credential_id" to Cbor.bytes(id(4)),"approver" to Cbor.bytes(id(6)),"target" to Cbor.bytes(id(6)),"scope" to Cbor.ofMap("purpose" to Cbor.text("authenticate"),"service" to Cbor.text("rba"),"operation" to Cbor.text("authenticate")))
        val offer=mutate(msg(35),"grants",Value.Arr(listOf(grant)))
        var count=0
        fun ck(ok:Boolean){check(ok){"enrollment check ${count+1}"};count++}
        fun rejects(f:()->Unit)=runCatching(f).exceptionOrNull() is V2Wire.Invalid
        fun toShare(s:V2Enrollment,d:Int=0){s.acceptStart(start(d),100,1000);s.share(id(4),tk,bk,if(d==0)"004827".toByteArray() else null,101,2000)}
        fun toProof(s:V2Enrollment):V2Enrollment.Proofs {toShare(s);val confirm=s.confirm(msg(32),102,3000);return s.approve(confirm.contextHash,103,4000)}
        fun toOffer(s:V2Enrollment){val p=toProof(s);s.evidence(listOf(byteArrayOf(1)),listOf(byteArrayOf(2)),sign(p.transport,1),sign(p.biometric,2),emptyList(),104,5000)}
        fun stage(s:V2Enrollment,store:Store):ByteArray{toOffer(s);val digest=s.acceptOffer(offer,105,6000);s.stageOffer(digest,store,106,7000);return digest}
        fun receipt(hash:ByteArray)=mutate(msg(37),"offer_hash",Cbor.bytes(hash))
        if(trace!=null){
            fun at(i:Int)=trace.getOrElse(i){0}.toInt() and 255
            val d=at(0)%2;val fault=at(1)%9;val(s,h)=session(d);val store=Store()
            toShare(s,d)
            if(fault==1){ck(rejects{s.confirm(mutate(msg(32),"confirmation",Cbor.bytes(b(99))),102,3000)})}
            else {
                val confirmation=s.confirm(msg(32),102,3000)
                if(fault==2){ck(rejects{s.approve(b(99),103,4000)})}
                else {
                    val proofs=s.approve(confirmation.contextHash,103,4000)
                    if(fault==3){ck(rejects{s.evidence(listOf(byteArrayOf(1)),listOf(byteArrayOf(2)),sign(proofs.transport,1),sign(proofs.biometric,1),emptyList(),104,5000)})}
                    else {
                        s.evidence(listOf(byteArrayOf(1)),listOf(byteArrayOf(2)),sign(proofs.transport,1),sign(proofs.biometric,2),emptyList(),104,5000)
                        val hash=s.acceptOffer(offer,105,6000)
                        if(fault==4){ck(rejects{s.stageOffer(b(99),store,106,7000)})}
                        else {
                            s.stageOffer(hash,store,106,7000)
                            ck(!store.active)
                            when(fault){
                                5->ck(rejects{s.receipt(receipt(b(99)),store,107,8000)})
                                6->{s.close();ck(rejects{s.receipt(receipt(hash),store,107,8000)})}
                                7->ck(rejects{s.receipt(receipt(hash),store,220,8000)})
                                else->{s.receipt(receipt(hash),store,107,8000);ck(store.active)}
                            }
                            ck(rejects{s.receipt(receipt(hash),store,107,8000)})
                        }
                    }
                }
            }
            ck(h.closed);ck(store.active==(fault==0||fault==8))
            for(op in trace.drop(2).take(32))when((op.toInt() and 255)%3){
                0->ck(rejects{s.acceptStart(start(d),100,1000)})
                1->ck(s.cancel()==null)
                else->s.close()
            }
            ck(store.active==(fault==0||fault==8));return count
        }
        for(d in 0..1){
            val(s,h)=session(d);val challenges=s.acceptStart(start(d),100,1000)
            ck(s.operationDeadline()==121000L)
            ck(challenges.transport.contentEquals(hex(fixtures[d][3])));ck(challenges.biometric.contentEquals(hex(fixtures[d][4])))
            val code=if(d==0)"004827".toByteArray() else null
            val share=s.share(id(4),tk,bk,code,101,2000);ck(share.message.kind==V2Message.Kind.ENROLLSHARE);ck(if(d==0)share.displayCode==null&&code!!.all{it==0.toByte()} else share.displayCode!!.contentEquals("004827".toByteArray()))
            share.displayCode?.fill(0);val confirmation=s.confirm(msg(32),102,3000);ck(h.started&&h.confirmed&&h.closed);ck(confirmation.contextHash.contentEquals(hex(fixtures[d][2])))
            val proofs=s.approve(confirmation.contextHash,103,4000);val ev=s.evidence(listOf(byteArrayOf(1)),listOf(byteArrayOf(2)),sign(proofs.transport,1),sign(proofs.biometric,2),emptyList(),104,5000);ck(ev.kind==V2Message.Kind.ENROLLEVIDENCE)
            val store=Store();val hash=s.acceptOffer(offer,105,6000);ck(store.saved==null&&!store.active);val ack=s.stageOffer(hash,store,106,7000);ck(raw(field(ack,"offer_hash")).contentEquals(hash)&&store.saved!=null&&!store.active)
            s.receipt(receipt(hash),store,107,8000);ck(store.active);ck(rejects{s.receipt(receipt(hash),store,107,8000)})
            val initial=V2Enrollment.Pending.decode(store.saved!!).initialPolicy()!!
            ck(initial.revision==1L);ck(initial.digest().contentEquals(V2Message.hash(V2Message.Domain.POLICY,Cbor.ofMap("revision" to Cbor.uint(1),"grants" to Value.Arr(listOf(grant))))))
        }
        session().first.also{ s->toOffer(s);val empty=mutate(offer,"grants",Value.Arr(emptyList()));val hash=s.acceptOffer(empty,105,6000);val store=Store();s.stageOffer(hash,store,106,7000);ck(V2Enrollment.Pending.decode(store.saved!!).initialPolicy()==null) }
        ck(rejects{session().first.acceptStart(start(0),99,1000)})
        ck(rejects{session().first.acceptStart(start(0),220,1000)})
        session().first.also{it.acceptStart(start(0),100,1000);ck(rejects{it.share(id(4),tk,bk,null,101,2000)})}
        session().first.also{it.acceptStart(start(0),100,1000);ck(rejects{it.share(id(4),tk,tk,"004827".toByteArray(),101,2000)})}
        session().first.also{it.acceptStart(start(0),100,1000);ck(rejects{it.share(id(4),tk,bk,"004827".toByteArray(),101,121000)})}
        session().let{(s,h)->toShare(s);ck(rejects{s.confirm(mutate(msg(32),"confirmation",Cbor.bytes(b(99))),102,3000)});ck(h.closed);ck(rejects{s.confirm(msg(32),102,3000)})}
        session().let{(s,h)->toShare(s);ck(s.cancel()?.kind==V2Message.Kind.ENROLLCANCEL&&h.closed);ck(s.cancel()==null)}
        session().first.also{toShare(it);it.confirm(msg(32),102,3000);ck(rejects{it.approve(b(99),103,4000)})}
        session().first.also{val p=toProof(it);ck(rejects{it.evidence(listOf(byteArrayOf(1)),listOf(byteArrayOf(2)),sign(p.transport,1),sign(p.biometric,1),emptyList(),104,5000)})}
        session().first.also{toOffer(it);ck(rejects{it.acceptOffer(msg(35),105,6000)})} // delegated initial grant forbidden
        session().first.also{toOffer(it);it.acceptOffer(offer,105,6000);val store=Store();ck(rejects{it.stageOffer(b(99),store,106,7000)});ck(store.saved==null&&!store.active)}
        session().first.also{toOffer(it);val hash=it.acceptOffer(offer,105,6000);val store=Store().apply{failStage=true};ck(runCatching{it.stageOffer(hash,store,106,7000)}.isFailure);ck(!store.active)}
        session().first.also{val store=Store();stage(it,store);ck(rejects{it.receipt(receipt(b(99)),store,107,8000)});ck(!store.active&&store.saved!=null)}
        session().first.also{val store=Store();val hash=stage(it,store);store.failActivate=true;ck(runCatching{it.receipt(receipt(hash),store,107,8000)}.isFailure);ck(!store.active&&store.saved!=null)}
        fun recovery(store:Store,now:Long=107):V2Enrollment.Recovery=V2Enrollment.Pending.decode(store.saved!!).recover(id(3),hk,id(4),tk,id(1),now,8000)
        session().first.also{val store=Store();stage(it,store);it.close();val r=recovery(store);ck(r.request().kind==V2Message.Kind.ENROLLSTATUS);r.accept(msg(23),store,108,9000);ck(store.active);ck(rejects{r.accept(msg(23),store,108,9000)})}
        session().first.also{val store=Store();stage(it,store);it.close();val pending=V2Enrollment.Pending.decode(store.saved!!);ck(rejects{pending.recover(id(3),pk,id(4),tk,id(1),107,8000)});ck(rejects{recovery(store,86505)});val r=recovery(store);r.request();ck(rejects{r.accept(mutate(msg(23),"session_id",Cbor.bytes(id(9))),store,108,9000)});ck(!store.active)}
        session().first.also{val store=Store();stage(it,store);it.close();val r=recovery(store);r.request();ck(rejects{r.accept(msg(23),store,108,68000)});ck(!store.active)}
        // Use a validated enrollment record; a fresh instance represents a
        // fresh authenticated channel after a lost receipt.
        val revokedStore=Store();session().first.also{stage(it,revokedStore);it.close()}
        val revRecord=V2Enrollment.Pending.decode(revokedStore.saved!!)
        fun revoke(sid:ByteArray=id(1),host:ByteArray=id(3),hostKey:ByteArray=hk,credential:ByteArray=id(4),key:ByteArray=tk)=V2Revocation(revRecord,host,hostKey,credential,key,sid,107,8000)
        fun revReceipt(sid:ByteArray=id(1),cid:ByteArray=id(4))=V2Message.Message.create(V2Message.Kind.REVOKERECEIPT,Cbor.ofMap("session_id" to Cbor.bytes(sid),"credential_id" to Cbor.bytes(cid)))
        var committed=0
        ck(rejects{revoke(host=id(9))});ck(rejects{revoke(hostKey=pk)});ck(rejects{revoke(credential=id(9))});ck(rejects{revoke(key=bk)});ck(rejects{revoke(sid=id(0))})
        revoke().also{r->ck(rejects{r.receipt(revReceipt(),108,9000){committed++}});ck(committed==0)}
        revoke().also{r->val request=r.request(107,8000);ck(request.kind==V2Message.Kind.REVOKE);ck(raw(field(request,"token")).contentEquals(revRecord.revocationToken()));ck(rejects{r.request(108,9000)});ck(rejects{r.receipt(revReceipt(),108,9000){committed++}})}
        for(bad in listOf(revReceipt(id(9)),revReceipt(cid=id(9)),msg(23)))revoke().also{r->r.request(107,8000);ck(rejects{r.receipt(bad,108,9000){committed++}});ck(rejects{r.receipt(revReceipt(),108,9000){committed++}})}
        for((w,m) in listOf(106L to 9000L,108L to 7999L,167L to 9000L,108L to 68000L))revoke().also{r->r.request(107,8000);ck(rejects{r.receipt(revReceipt(),w,m){committed++}})}
        revoke().also{r->r.request(107,8000);r.cancel();ck(rejects{r.receipt(revReceipt(),108,9000){committed++}})}
        revoke().also{r->r.request(107,8000);ck(runCatching{r.receipt(revReceipt(),108,9000){error("test storage failure")}}.isFailure);ck(rejects{r.receipt(revReceipt(),108,9000){committed++}})}
        ck(committed==0)
        revoke(id(2)).also{r->r.request(107,8000);r.receipt(revReceipt(id(2)),108,9000){committed++};ck(committed==1);ck(rejects{r.receipt(revReceipt(id(2)),108,9000){committed++}});ck(committed==1)}
        // Offline cleanup tokens are scoped to the confirmed host ID AND key.
        fun oldRecord(host:ByteArray=id(3),hostKey:ByteArray=hk,credential:ByteArray=id(8)):V2Enrollment.Pending {
            val r=V2Wire.decodePayload(revRecord.encode());val oldOffer=replace(replace(r["offer"] as Value.Map,"credential_id",Cbor.bytes(credential)),"grants",Value.Arr(emptyList()))
            return V2Enrollment.Pending.decode(V2Wire.encodePayload(replace(replace(replace(r,"host_id",Cbor.bytes(host)),"host_key",Cbor.bytes(hostKey)),"offer",oldOffer)))
        }
        fun sendCleanup(records:List<V2Enrollment.Pending>):V2Message.Message {
            val s=session().first;val p=toProof(s)
            return s.evidence(listOf(byteArrayOf(1)),listOf(byteArrayOf(2)),sign(p.transport,1),sign(p.biometric,2),records,104,5000)
        }
        val old=oldRecord();val clean=sendCleanup(listOf(old));ck((field(clean,"cleanup_tokens") as Value.Arr).items.single()==Cbor.bytes(old.revocationToken()))
        ck(rejects{sendCleanup(listOf(oldRecord(host=id(9))))})
        ck(rejects{sendCleanup(listOf(oldRecord(hostKey=pk)))})
        ck(rejects{sendCleanup(listOf(oldRecord(credential=id(4))))})
        ck(rejects{sendCleanup(listOf(old,old))})
        ck(rejects{sendCleanup(listOf(old,oldRecord(credential=id(9))))})
        ck(rejects{sendCleanup(List(33){old})})
        return count
    }
}
