package io.github.burtvadr.rba.transport

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.burtvadr.rba.keystore.V2HardwareKeys
import io.github.burtvadr.rba.protocol.V2Enrollment
import org.conscrypt.Conscrypt
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.net.InetAddress
import java.net.Socket
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Principal
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.net.ssl.*

/** Physical Android test. Both endpoints use the selected native provider;
 * the client must use its actual opaque, hardware-attested transport key.
 * Cross-provider Linux/Android acceptance is separate. */
@RunWith(AndroidJUnit4::class)
class V2TlsHardwareTest {
    @Test fun opaqueTransportKeyCompletesMutualTlsAndExporterAgrees(){
        val context=InstrumentationRegistry.getInstrumentation().targetContext
        val rng=SecureRandom();val tc=ByteArray(32).apply{rng.nextBytes(this)};val bc=ByteArray(32).apply{rng.nextBytes(this)}
        val device=V2HardwareKeys.generate(context,V2Enrollment.Challenges(tc,bc))
        val ks=KeyStore.getInstance("AndroidKeyStore").apply{load(null)}
        val alias="rba-test-tls-${UUID.randomUUID()}"
        val executor=Executors.newSingleThreadExecutor()
        try{
            KeyPairGenerator.getInstance("EC","AndroidKeyStore").apply{initialize(KeyGenParameterSpec.Builder(alias,KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1")).setDigests(KeyProperties.DIGEST_SHA256,KeyProperties.DIGEST_NONE).setUserAuthenticationRequired(false).build())}.generateKeyPair()
            val host=ks.getCertificate(alias) as X509Certificate;val privateKey=ks.getKey(alias,null) as PrivateKey
            val serverKeys=object:X509ExtendedKeyManager(){
                override fun getClientAliases(t:String?,i:Array<out Principal>?):Array<String>?=null
                override fun chooseClientAlias(t:Array<out String>?,i:Array<out Principal>?,s:Socket?):String?=null
                override fun getServerAliases(t:String?,i:Array<out Principal>?)=if(t=="EC")arrayOf(alias)else null
                override fun chooseServerAlias(t:String?,i:Array<out Principal>?,s:Socket?)=if(t=="EC")alias else null
                override fun chooseEngineServerAlias(t:String?,i:Array<out Principal>?,e:SSLEngine?)=if(t=="EC")alias else null
                override fun getPrivateKey(a:String?)=if(a==alias)privateKey else null
                override fun getCertificateChain(a:String?)=if(a==alias)arrayOf(host)else null
            }
            val clientTrust=object:X509TrustManager{
                override fun getAcceptedIssuers():Array<X509Certificate> = emptyArray()
                override fun checkServerTrusted(c:Array<out X509Certificate>?,a:String?):Unit=throw CertificateException("test server only")
                override fun checkClientTrusted(c:Array<out X509Certificate>?,a:String?){
                    if(c?.size!=1||!V2TlsTrust.point(c.single()).contentEquals(device.transportPoint()))throw CertificateException("unexpected hardware key")
                }
            }
            val provider=Conscrypt.newProvider()
            val serverContext=SSLContext.getInstance("TLSv1.3",provider).apply{init(arrayOf<KeyManager>(serverKeys),arrayOf<TrustManager>(clientTrust),rng)}
            val clientContext=SSLContext.getInstance("TLSv1.3",provider).apply{init(arrayOf<KeyManager>(device.tlsKeyManager()),arrayOf<TrustManager>(V2TlsTrust.production(V2TlsTrust.point(host))),rng)}
            val server=serverContext.serverSocketFactory.createServerSocket(0,1,InetAddress.getLoopbackAddress()) as SSLServerSocket
            server.use{listener->
                listener.soTimeout=10000;listener.needClientAuth=true;listener.enabledProtocols=arrayOf("TLSv1.3")
                val result=executor.submit<ByteArray>{
                    (listener.accept() as SSLSocket).use{s->
                        s.soTimeout=10000;s.needClientAuth=true;s.enabledProtocols=arrayOf("TLSv1.3");Conscrypt.setUseSessionTickets(s,false);Conscrypt.setApplicationProtocols(s,arrayOf("rba/2"));s.startHandshake()
                        check(s.session.protocol=="TLSv1.3"&&Conscrypt.getApplicationProtocol(s)=="rba/2")
                        check(V2TlsTrust.point(s.session.peerCertificates.single() as X509Certificate).contentEquals(device.transportPoint()))
                        val b=checkNotNull(Conscrypt.exportKeyingMaterial(s,"EXPORTER-Channel-Binding",byteArrayOf(),32));s.outputStream.write(7);s.outputStream.flush();b
                    }
                }
                val exporter=(clientContext.socketFactory.createSocket(InetAddress.getLoopbackAddress(),listener.localPort) as SSLSocket).use{s->
                    s.soTimeout=10000;s.enabledProtocols=arrayOf("TLSv1.3");Conscrypt.setUseSessionTickets(s,false);Conscrypt.setApplicationProtocols(s,arrayOf("rba/2"));s.startHandshake()
                    assertEquals("TLSv1.3",s.session.protocol);assertEquals("rba/2",Conscrypt.getApplicationProtocol(s));assertEquals(7,s.inputStream.read());checkNotNull(Conscrypt.exportKeyingMaterial(s,"EXPORTER-Channel-Binding",byteArrayOf(),32))
                }
                assertEquals(32,exporter.size);assertTrue(exporter.any{it!=0.toByte()});assertArrayEquals(result.get(12,TimeUnit.SECONDS),exporter)
            }
        }finally{executor.shutdownNow();try{ks.deleteEntry(alias)}finally{V2HardwareKeys.deleteUnrecorded(device.id(),device.transportPoint(),device.biometricPoint())}}
    }
}
