package io.github.burtvadr.rba.transport

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import io.github.burtvadr.rba.keystore.V2HardwareKeys
import io.github.burtvadr.rba.protocol.Cbor
import io.github.burtvadr.rba.protocol.V2Message
import io.github.burtvadr.rba.protocol.V2Enrollment
import io.github.burtvadr.rba.session.V2DeviceStore
import org.conscrypt.Conscrypt
import java.io.ByteArrayInputStream
import java.io.SequenceInputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Date
import java.util.UUID
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit
import javax.net.ssl.KeyManager
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.security.auth.x500.X500Principal

/** Unactivated V2 transport. No protocol fallback. Call from a serialized
 * connection owner, never from the UI thread. All routing is locally chosen. */
internal object V2TlsClient {
    private const val EXPORTER="EXPORTER-Channel-Binding"
    private val rng=SecureRandom()
    private val provider by lazy { Conscrypt.newProvider() }
    private val watchdog=ScheduledThreadPoolExecutor(1){r->Thread(r,"rba-v2-tls-deadline").apply{isDaemon=true}}.apply{removeOnCancelPolicy=true}
    private fun hash(b:ByteArray)=MessageDigest.getInstance("SHA-256").digest(b)
    private fun random(n:Int)=ByteArray(n).apply{rng.nextBytes(this);check(any{it!=0.toByte()})}
    private fun now()=android.os.SystemClock.elapsedRealtime()
    private fun <T> bounded(socket:Socket,deadline:Long,block:()->T):T{
        val remaining=deadline-now();require(remaining in 1..120000)
        val close=watchdog.schedule({runCatching{socket.close()}},remaining,TimeUnit.MILLISECONDS)
        try {val result=block();check(now()<deadline&&!socket.isClosed);return result}
        catch(e:Exception){runCatching{socket.close()};throw e}
        finally{close.cancel(false)}
    }
    enum class EnrolledPurpose { AUTHENTICATION, POLICY, RECOVERY }
    private enum class Mode(val alpn:String,val purpose:Long){AUTHENTICATION("rba/2",0),POLICY("rba/2",1),RECOVERY("rba/2",2),REVOCATION("rba/2",3),ENROLL("rba-enroll/2",-1)}
    private class Provisional:AutoCloseable{
        // Fresh, one-use keystore alias; never an enrolled credential or
        // reused on reconnect. A crash orphan has no authority to enroll.
        private val alias="rba-v2-provisional-${UUID.randomUUID()}"
        private val ks=KeyStore.getInstance("AndroidKeyStore").apply{load(null)}
        val identity:V2TlsIdentity
        init{
            check(!ks.containsAlias(alias));val t=System.currentTimeMillis()
            try{
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC,"AndroidKeyStore").apply{
                    initialize(KeyGenParameterSpec.Builder(alias,KeyProperties.PURPOSE_SIGN)
                        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                        .setDigests(KeyProperties.DIGEST_NONE,KeyProperties.DIGEST_SHA256)
                        .setCertificateSubject(X500Principal("CN=RBA provisional"))
                        .setCertificateSerialNumber(java.math.BigInteger(120,rng).add(java.math.BigInteger.ONE))
                        .setCertificateNotBefore(Date(t-60000)).setCertificateNotAfter(Date(t+300000))
                        .setUserAuthenticationRequired(false).build())
                }.generateKeyPair()
                val leaf=ks.getCertificate(alias) as X509Certificate
                check(leaf.subjectX500Principal==leaf.issuerX500Principal);leaf.verify(leaf.publicKey)
                val key=ks.getKey(alias,null) as PrivateKey
                check(key.encoded==null&&key.format==null)
                identity=V2TlsIdentity(key,leaf)
            }catch(e:Exception){runCatching{ks.deleteEntry(alias)};throw e}
        }
        override fun close(){ks.deleteEntry(alias)}
    }
    class Session internal constructor(host:ByteArray,credential:ByteArray,session:ByteArray,hn:ByteArray,dn:ByteArray,channel:ByteArray,hostKey:ByteArray){
        private val h=host.copyOf();private val c=credential.copyOf();private val s=session.copyOf();private val a=hn.copyOf();private val b=dn.copyOf();private val e=channel.copyOf();private val k=hostKey.copyOf()
        fun hostId()=h.copyOf();fun credentialId()=c.copyOf();fun sessionId()=s.copyOf();fun hostNonce()=a.copyOf();fun deviceNonce()=b.copyOf();fun exporter()=e.copyOf();fun hostKey()=k.copyOf()
    }
    internal class Channel private constructor(private val socket:SSLSocket,private val carrier:Socket,private val mode:Mode,private val provisional:Provisional?,private val binding:ByteArray,private val hostKey:ByteArray,private val clientKey:ByteArray,private val hostCert:ByteArray,private val clientCert:ByteArray):AutoCloseable{
        @Volatile private var session:Session?=null
        private val closedFlag=java.util.concurrent.atomic.AtomicBoolean(false)
        private val closed get()=closedFlag.get()
        private val readLock=Any();private val writeLock=Any()
        private var enrollmentClaimed=false
        private val input=socket.inputStream;private val output=socket.outputStream
        fun session():Session=checkNotNull(session)
        fun localTransportKey():ByteArray=clientKey.copyOf()
        @Synchronized fun enrollment(pake:V2Enrollment.Pake):V2Enrollment{
            check(mode==Mode.ENROLL&&!closed&&!enrollmentClaimed);enrollmentClaimed=true
            return V2Enrollment(binding.copyOf(),hostCert.copyOf(),clientCert.copyOf(),hostKey.copyOf(),clientKey.copyOf(),pake)
        }
        private fun allowIn(k:V2Message.Kind):Boolean{
            return when(mode){
                Mode.ENROLL->k in setOf(V2Message.Kind.ENROLLSTART,V2Message.Kind.ENROLLCONFIRMA,V2Message.Kind.ENROLLOFFER,V2Message.Kind.ENROLLRECEIPT,V2Message.Kind.ENROLLCANCEL)
                Mode.AUTHENTICATION->if(session==null)k==V2Message.Kind.HELLO else k in setOf(V2Message.Kind.AUTHREQUEST,V2Message.Kind.MATCHED,V2Message.Kind.CANCEL,V2Message.Kind.AUTHRESULT)
                Mode.POLICY->if(session==null)k==V2Message.Kind.HELLO else k in setOf(V2Message.Kind.POLICYOFFER,V2Message.Kind.POLICYRECEIPT)
                Mode.RECOVERY->if(session==null)k==V2Message.Kind.HELLO else k==V2Message.Kind.ENROLLSTATUSRESULT
                Mode.REVOCATION->if(session==null)k==V2Message.Kind.HELLO else k==V2Message.Kind.REVOKERECEIPT
            }
        }
        private fun allowOut(k:V2Message.Kind):Boolean=when(mode){
            Mode.ENROLL->k in setOf(V2Message.Kind.ENROLLSHARE,V2Message.Kind.ENROLLCONFIRMB,V2Message.Kind.ENROLLEVIDENCE,V2Message.Kind.ENROLLSTAGED,V2Message.Kind.ENROLLCANCEL)
            Mode.AUTHENTICATION->if(session==null)k==V2Message.Kind.HELLOACK else k in setOf(V2Message.Kind.NUMBERENTRY,V2Message.Kind.AUTHRESPONSE,V2Message.Kind.CANCEL)
            Mode.POLICY->if(session==null)k==V2Message.Kind.HELLOACK else k==V2Message.Kind.POLICYDECISION
            Mode.RECOVERY->if(session==null)k==V2Message.Kind.HELLOACK else k==V2Message.Kind.ENROLLSTATUS
            Mode.REVOCATION->if(session==null)k==V2Message.Kind.HELLOACK else k==V2Message.Kind.REVOKE
        }
        fun read(deadline:Long=now()+30000):V2Message.Message=synchronized(readLock){
            check(!closed)
            try{
                val first=bounded(carrier,deadline){input.read().also{check(it>=0)}}
                val message=bounded(carrier,minOf(deadline,now()+5000)){
                    V2Message.Message.read(SequenceInputStream(ByteArrayInputStream(byteArrayOf(first.toByte())),input)).also{check(allowIn(it.kind))}
                }
                // Terminal receipts are informational and are processed by the
                // owning state machine after transport closure, never reused.
                if(message.kind in setOf(V2Message.Kind.AUTHRESULT,V2Message.Kind.ENROLLRECEIPT,V2Message.Kind.ENROLLSTATUSRESULT,V2Message.Kind.REVOKERECEIPT,V2Message.Kind.POLICYRECEIPT)) {
                    // The peer can reply before the local flush returns. Let
                    // that bounded write finish before closing the carrier.
                    synchronized(writeLock){close()}
                }
                message
            }catch(e:Exception){close();throw e}
        }
        fun write(m:V2Message.Message,deadline:Long=now()+5000):Unit=synchronized(writeLock){
            check(!closed)
            try{check(allowOut(m.kind));bounded(carrier,minOf(deadline,now()+5000)){output.write(m.encode());output.flush()}}
            catch(e:Exception){close();throw e}
        }
        private fun hello(record:V2Enrollment.Pending){
            val deadline=now()+5000;val m=read(deadline);val p=m.payload()
            fun b(name:String)=((p[name] as? Cbor.Value.Bytes)?:error("V2 HELLO missing field")).value.copyOf()
            val host=b("host_id");val id=b("session_id");val nonce=b("host_nonce");val dn=random(32)
            check(host.contentEquals(record.hostId())&&nonce.any{it!=0.toByte()})
            val capabilities=Cbor.Value.Arr(listOf("attestation","number-match","strong-biometric","tls-exporter").map{Cbor.text(it)})
            val ack=V2Message.Message.create(V2Message.Kind.HELLOACK,Cbor.ofMap("v" to Cbor.uint(2),"host_id" to Cbor.bytes(host),"session_id" to Cbor.bytes(id),"host_nonce" to Cbor.bytes(nonce),"device_nonce" to Cbor.bytes(dn),"credential_id" to Cbor.bytes(record.credentialId()),"purpose" to Cbor.uint(mode.purpose),"capabilities" to capabilities))
            write(ack,deadline);session=Session(host,record.credentialId(),id,nonce,dn,binding,hostKey)
        }
        override fun close(){if(!closedFlag.compareAndSet(false,true))return;try{carrier.close()}finally{try{socket.close()}finally{provisional?.close()}}}
        companion object{
            private fun connect(address:InetSocketAddress,mode:Mode,identity:javax.net.ssl.X509ExtendedKeyManager,trust:V2TlsTrust,provisional:Provisional?):Channel{
                require(!address.isUnresolved)
                val raw=Socket();var ssl:SSLSocket?=null;val deadline=now()+5000
                try{
                    val context=SSLContext.getInstance("TLSv1.3",provider)
                    context.init(arrayOf<KeyManager>(identity),arrayOf<TrustManager>(trust),rng)
                    bounded(raw,deadline){raw.connect(address,(deadline-now()).coerceAtLeast(1).toInt())}
                    val s=context.socketFactory.createSocket(raw,address.address.hostAddress,address.port,true) as SSLSocket;ssl=s
                    check(Conscrypt.isConscrypt(s));s.useClientMode=true;s.enabledProtocols=arrayOf("TLSv1.3")
                    Conscrypt.setUseSessionTickets(s,false);Conscrypt.setApplicationProtocols(s,arrayOf(mode.alpn))
                    bounded(raw,deadline){s.startHandshake()}
                    check(s.session.protocol=="TLSv1.3"&&Conscrypt.getApplicationProtocol(s)==mode.alpn)
                    val remote=s.session.peerCertificates.single() as X509Certificate
                    val local=checkNotNull(s.session.localCertificates).single() as X509Certificate
                    trust.checkServerTrusted(arrayOf(remote),"EC")
                    val hp=V2TlsTrust.point(remote);val cp=V2TlsTrust.point(local)
                    check(!hp.contentEquals(cp))
                    val expected=checkNotNull(identity.getCertificateChain("rba-transport")).single()
                    check(expected.encoded.contentEquals(local.encoded))
                    val binding=checkNotNull(Conscrypt.exportKeyingMaterial(s,EXPORTER,byteArrayOf(),32));check(binding.size==32&&binding.any{it!=0.toByte()})
                    return Channel(s,raw,mode,provisional,binding,hp,cp,hash(remote.encoded),hash(local.encoded))
                }catch(e:Exception){runCatching{ssl?.close()};runCatching{raw.close()};runCatching{provisional?.close()};throw e}
            }
            fun enrolled(address:InetSocketAddress,store:V2DeviceStore,credential:ByteArray,purpose:EnrolledPurpose):Channel{
                val record=checkNotNull(if(purpose==EnrolledPurpose.RECOVERY)store.pending(credential)else store.active(credential))
                val keys=V2HardwareKeys.load(record.credentialId(),record.transportKey(),record.biometricKey())
                val mode=when(purpose){
                    EnrolledPurpose.AUTHENTICATION->Mode.AUTHENTICATION
                    EnrolledPurpose.POLICY->Mode.POLICY
                    EnrolledPurpose.RECOVERY->Mode.RECOVERY
                }
                val c=connect(address,mode,keys.tlsKeyManager(),V2TlsTrust.production(record.hostKey()),null)
                try{check(c.clientKey.contentEquals(record.transportKey()));c.hello(record);return c}catch(e:Exception){c.close();throw e}
            }
            fun revocation(address:InetSocketAddress,store:V2DeviceStore,credential:ByteArray):Channel {
                val record=store.revoking(credential)
                val identity=V2HardwareKeys.revocationKeyManager(record.credentialId(),record.transportKey())
                val c=connect(address,Mode.REVOCATION,identity,V2TlsTrust.production(record.hostKey()),null)
                try{check(c.clientKey.contentEquals(record.transportKey()));c.hello(record);return c}catch(e:Exception){c.close();throw e}
            }
            /** Only call after a separate explicit local pairing action. */
            fun provisional(address:InetSocketAddress):Channel{
                val id=Provisional();return connect(address,Mode.ENROLL,id.identity,V2TlsTrust.enrollment(),id)
            }
        }
    }
}
