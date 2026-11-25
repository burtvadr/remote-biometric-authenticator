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

/** JVM signatures exercise protocol evidence only, not physical biometrics. */
object V2AuthenticationTests {
    private fun hex(s:String)=s.chunked(2).map{it.toInt(16).toByte()}.toByteArray()
    private fun id(n:Int)=ByteArray(16){n.toByte()}
    private fun b(n:Int)=ByteArray(32){n.toByte()}
    private fun replace(v:Value.Map,k:String,x:Value)=Value.Map(v.entries.map{(key,value)->key to if(key==Value.Text(k)) x else value})
    fun run(dir:File, trace:ByteArray?=null):Int {
        val rows=File(dir,"v2-message.tsv").readLines().filterNot{it.startsWith('#')}.associate{val f=it.split('\t'); f[0] to f}
        fun msg(n:Int)=V2Message.Message.read(ByteArrayInputStream(hex(rows.getValue("msg-$n")[2])))
        fun signed(n:Int, domain:String):V2Message.Message {
            val m=msg(n);val signature=hex(rows.getValue("RBA-V2-$domain-valid")[3].split(':')[2])
            return V2Message.Message.create(m.kind,replace(m.payload(),"signature",Cbor.bytes(signature)))
        }
        val request=signed(12,"AUTH-REQUEST"); val matched=signed(14,"MATCHED")
        val hostKey=hex(rows.getValue("RBA-V2-AUTH-REQUEST-valid")[3].split(':')[1]);val bioKey=hex(rows.getValue("RBA-V2-AUTH-REQUEST-wrong-key")[3].split(':')[1])
        val offer=msg(20).payload();val pc=Cbor.ofMap("revision" to offer["revision"]!!,"grants" to offer["grants"]!!)
        val grants=offer["grants"] as Value.Arr
        fun policy(local:Value.Arr=grants)=V2DevicePolicy.fromCommitted(id(3),id(4),id(6),pc,(offer["digest"] as Value.Bytes).value,local)
        val p=policy(); val deny=policy(Value.Arr(emptyList()))
        fun session(channel:ByteArray=b(3))=V2Authentication(id(3),id(4),id(1),b(1),b(2),channel,hostKey,bioKey)
        val params=AlgorithmParameters.getInstance("EC").apply{init(ECGenParameterSpec("secp256r1"))}.getParameterSpec(ECParameterSpec::class.java)
        fun sign(bytes:ByteArray,n:Long):ByteArray=Signature.getInstance("SHA256withECDSAinP1363Format").run{
            initSign(KeyFactory.getInstance("EC").generatePrivate(ECPrivateKeySpec(BigInteger.valueOf(n),params)));update(bytes);sign()
        }
        var count=0
        fun ck(ok:Boolean){check(ok){"authentication check ${count+1}"};count++}
        fun rejected(f:()->Unit)=runCatching(f).exceptionOrNull() is V2Wire.Invalid
        fun number(s:V2Authentication){s.acceptRequest(request,p,100,1000);s.enterNumber("001234",p,101,2000)}
        fun ready(s:V2Authentication):ByteArray {number(s);return s.acceptMatch(matched,p,102,3000)}
        if(trace!=null){
            fun at(i:Int)=trace.getOrElse(i){0}.toInt() and 255
            val stage=at(0)%4;val fault=at(1)%6
            val s=session();var tr:ByteArray?=null
            if(stage>=1)s.acceptRequest(request,p,100,1000)
            if(stage>=2)s.enterNumber("001234",p,101,2000)
            if(stage>=3)tr=s.acceptMatch(matched,p,102,3000)
            fun attempt(){when(stage){
                0->s.acceptRequest(if(fault==1)msg(12) else request,if(fault==2)deny else p,if(fault==3)160 else 100,1000)
                1->s.enterNumber(if(fault==1)"12345" else "001234",if(fault==2)deny else p,if(fault==3)160 else 101,if(fault==4)61000 else 2000)
                2->s.acceptMatch(if(fault==1)msg(14) else matched,if(fault==2)deny else p,if(fault==3)160 else 102,if(fault==4)61000 else 3000)
                else->s.completeBiometric(sign(tr!!,if(fault==1)1 else 2),if(fault==2)deny else p,if(fault==3)160 else 103,if(fault==4)61000 else 4000)
            }}
            if(fault==5)s.invalidate()
            val allowed=fault==0||(stage==0&&fault==4)
            if(allowed){attempt();ck(true)}else ck(rejected{attempt()})
            ck(rejected{attempt()});s.invalidate()
            for(op in trace.drop(2).take(32))when((op.toInt() and 255)%3){
                0->ck(rejected{s.acceptRequest(request,p,100,1000)})
                1->ck(rejected{s.acceptResult(msg(17),104,5000)})
                else->ck(s.cancel()==null)
            }
            return count
        }
        val s=session(); val transcript=ready(s)
        val expires=((request.payload()["core"] as Value.Map)["expires_at"] as Value.Uint).value
        ck(s.operationDeadline()==1000+(expires-100)*1000)
        val expected=hex(rows.getValue("RBA-V2-AUTH-RESPONSE")[3].split(':')[0]);ck(transcript.contentEquals(expected))
        val response=s.completeBiometric(sign(transcript,2),p,103,4000);ck(response.kind==V2Message.Kind.AUTHRESPONSE)
        ck(s.acceptResult(msg(17),104,5000));ck(rejected{s.acceptResult(msg(17),104,5000)})
        ck(rejected{session(b(9)).acceptRequest(request,p,100,1000)})
        ck(rejected{session().acceptRequest(msg(12),p,100,1000)})
        ck(rejected{session().acceptRequest(request,deny,100,1000)})
        ck(rejected{session().acceptRequest(request,p,94,1000)})
        ck(rejected{session().acceptRequest(request,p,160,1000)})
        ck(rejected{session().enterNumber("001234",p,100,1000)})
        session().also{it.acceptRequest(request,p,100,1000);ck(rejected{it.enterNumber("001234",p,100,61000)})}
        session().also{it.acceptRequest(request,p,100,1000);ck(rejected{it.enterNumber("001234",p,99,2000)})}
        session().also{it.acceptRequest(request,p,100,1000);ck(rejected{it.enterNumber("001234",deny,101,2000)})}
        session().also{number(it);ck(rejected{it.enterNumber("001234",p,101,2000)});ck(rejected{it.acceptMatch(matched,p,102,3000)})}
        session().also{number(it);ck(rejected{it.acceptMatch(msg(14),p,102,3000)})}
        session().also{val tr=ready(it);ck(rejected{it.completeBiometric(sign(tr,1),p,103,4000)});ck(rejected{it.completeBiometric(sign(tr,2),p,103,4000)})}
        session().also{val tr=ready(it);ck(rejected{it.completeBiometric(sign(tr,2),deny,103,4000)})}
        session().also{val tr=ready(it);ck(rejected{it.completeBiometric(sign(tr,2),p,160,4000)})}
        session().also{number(it);ck(it.cancel()?.kind==V2Message.Kind.CANCEL);ck(it.cancel()==null);ck(rejected{it.acceptMatch(matched,p,102,3000)})}
        session().also{val tr=ready(it);it.completeBiometric(sign(tr,2),p,103,4000);val r=msg(17);val wrong=V2Message.Message.create(r.kind,replace(r.payload(),"request_id",Cbor.bytes(id(9))));ck(rejected{it.acceptResult(wrong,104,5000)})}
        return count
    }
}
