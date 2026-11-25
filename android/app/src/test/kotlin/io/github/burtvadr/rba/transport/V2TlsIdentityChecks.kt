package io.github.burtvadr.rba.transport

import java.io.File
import java.net.InetAddress
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.net.ssl.KeyManager
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.TrustManagerFactory

/** Real JSSE loopback TLS and trust-manager checks. These do not exercise
 * Conscrypt, Android Keystore, the exporter, or the Rust transport. */
internal object V2TlsIdentityChecks {
    private class Material(val key:PrivateKey,val cert:X509Certificate)
    private val password="test-only".toCharArray()
    private fun material(dir:File,name:String,curve:String="secp256r1"):Material {
        val file=File(dir,"$name.p12")
        val tool=File(System.getProperty("java.home"),"bin/keytool").absolutePath
        val proc=ProcessBuilder(tool,"-genkeypair","-alias","tls","-keyalg","EC","-groupname",curve,"-sigalg",if(curve=="secp256r1")"SHA256withECDSA" else "SHA384withECDSA","-dname","CN=RBA synthetic $name","-validity","1","-storetype","PKCS12","-keystore",file.absolutePath,"-storepass",String(password),"-keypass",String(password),"-noprompt").redirectErrorStream(true).redirectOutput(File(dir,"$name.log")).start()
        check(proc.waitFor(15,TimeUnit.SECONDS)&&proc.exitValue()==0){"keytool failed"}
        val ks=KeyStore.getInstance("PKCS12").apply{file.inputStream().use{load(it,password)}}
        return Material(ks.getKey("tls",password) as PrivateKey,ks.getCertificate("tls") as X509Certificate)
    }
    private fun loopback(host:Material,client:Material,pin:ByteArray,offerKey:Boolean,alpn:String):Boolean{
        val trust=TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply{
            init(KeyStore.getInstance(KeyStore.getDefaultType()).apply{load(null);setCertificateEntry("client",client.cert)})
        }
        val ks=KeyStore.getInstance("PKCS12").apply{load(null);setKeyEntry("host",host.key,password,arrayOf(host.cert))}
        val km=javax.net.ssl.KeyManagerFactory.getInstance(javax.net.ssl.KeyManagerFactory.getDefaultAlgorithm()).apply{init(ks,password)}
        val serverContext=SSLContext.getInstance("TLSv1.3").apply{init(km.keyManagers,trust.trustManagers,null)}
        val clientContext=SSLContext.getInstance("TLSv1.3").apply{init(if(offerKey)arrayOf<KeyManager>(V2TlsIdentity(client.key,client.cert))else emptyArray(),arrayOf<TrustManager>(V2TlsTrust.production(pin)),null)}
        val server=serverContext.serverSocketFactory.createServerSocket(0,1,InetAddress.getLoopbackAddress()) as SSLServerSocket
        server.soTimeout=3000;server.needClientAuth=true;server.enabledProtocols=arrayOf("TLSv1.3");server.sslParameters=server.sslParameters.apply{applicationProtocols=arrayOf("rba/2")}
        val executor=Executors.newSingleThreadExecutor()
        try{
            val task=executor.submit<Boolean>{runCatching{
                (server.accept() as SSLSocket).use{s->s.soTimeout=3000;s.startHandshake();check(s.applicationProtocol=="rba/2");check(s.session.peerCertificates.single().encoded.contentEquals(client.cert.encoded));s.outputStream.write(7);s.outputStream.flush();true}
            }.getOrDefault(false)}
            val accepted=runCatching{
                (clientContext.socketFactory.createSocket(InetAddress.getLoopbackAddress(),server.localPort) as SSLSocket).use{s->s.soTimeout=3000;s.enabledProtocols=arrayOf("TLSv1.3");s.sslParameters=s.sslParameters.apply{applicationProtocols=arrayOf(alpn)};s.startHandshake();check(s.applicationProtocol=="rba/2");check(s.inputStream.read()==7);true}
            }.getOrDefault(false)
            val serverAccepted=task.get(5,TimeUnit.SECONDS)
            return accepted&&serverAccepted
        }finally{server.close();executor.shutdownNow()}
    }
    fun run():Int {
        val dir=java.nio.file.Files.createTempDirectory("rba-tls-tests").toFile();var n=0
        fun expect(ok:Boolean){check(ok){"TLS check ${n+1} failed"};n++}
        try{
            val host=material(dir,"host");val client=material(dir,"client");val other=material(dir,"other");val wrongCurve=material(dir,"curve","secp384r1")
            val pin=V2TlsTrust.point(host.cert);val otherPin=V2TlsTrust.point(other.cert)
            val trusted=V2TlsTrust.production(pin)
            expect(runCatching{trusted.checkServerTrusted(arrayOf(host.cert),"EC")}.isSuccess)
            expect(runCatching{trusted.checkServerTrusted(arrayOf(other.cert),"EC")}.isFailure)
            expect(runCatching{trusted.checkServerTrusted(arrayOf(host.cert,other.cert),"EC")}.isFailure)
            expect(runCatching{trusted.checkServerTrusted(emptyArray(),"EC")}.isFailure)
            expect(runCatching{trusted.checkClientTrusted(arrayOf(client.cert),"EC")}.isFailure)
            expect(runCatching{V2TlsTrust.enrollment().checkServerTrusted(arrayOf(other.cert),"EC")}.isSuccess)
            expect(runCatching{V2TlsTrust.enrollment().checkServerTrusted(arrayOf(wrongCurve.cert),"EC")}.isFailure)
            val identity=V2TlsIdentity(client.key,client.cert)
            expect(identity.getPrivateKey("other")==null&&identity.getCertificateChain("other")==null)
            expect(identity.chooseClientAlias(arrayOf("RSA"),null,null)==null&&identity.getServerAliases("EC",null)==null)
            expect(loopback(host,client,pin,true,"rba/2"))
            expect(!loopback(host,client,otherPin,true,"rba/2"))
            expect(!loopback(host,client,pin,false,"rba/2"))
            expect(!loopback(host,client,pin,true,"rba-enroll/2"))
            return n
        }finally{dir.deleteRecursively()}
    }
}
fun main(){println("PASS: ${V2TlsIdentityChecks.run()} JVM TLS identity and loopback checks (JSSE, not Android/Conscrypt)")}
