package io.github.burtvadr.rba.transport

import io.github.burtvadr.rba.keystore.V2KeyEncoding
import java.net.Socket
import java.security.Principal
import java.security.PrivateKey
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import javax.net.ssl.SSLEngine
import javax.net.ssl.X509ExtendedKeyManager
import javax.net.ssl.X509TrustManager

/** Single identity, leaf-only TLS certificate carrier. No Android private-key
 * export, no default alias selection, no biometric key in this manager. */
internal class V2TlsIdentity(private val key:PrivateKey, private val leaf:X509Certificate):X509ExtendedKeyManager(){
    init { require(key.algorithm=="EC"); V2TlsTrust.point(leaf) }
    private fun alias(types:Array<out String>?)=if(types?.any{it=="EC"}==true) "rba-transport" else null
    override fun chooseClientAlias(keyType:Array<out String>?,issuers:Array<out Principal>?,socket:Socket?)=alias(keyType)
    override fun chooseEngineClientAlias(keyType:Array<out String>?,issuers:Array<out Principal>?,engine:SSLEngine?)=alias(keyType)
    override fun getClientAliases(keyType:String?,issuers:Array<out Principal>?)=if(keyType=="EC")arrayOf("rba-transport")else null
    override fun getServerAliases(keyType:String?,issuers:Array<out Principal>?):Array<String>?=null
    override fun chooseServerAlias(keyType:String?,issuers:Array<out Principal>?,socket:Socket?):String?=null
    override fun chooseEngineServerAlias(keyType:String?,issuers:Array<out Principal>?,engine:SSLEngine?):String?=null
    override fun getPrivateKey(alias:String?)=if(alias=="rba-transport")key else null
    override fun getCertificateChain(alias:String?)=if(alias=="rba-transport")arrayOf(leaf)else null
}
/** Exact key pin, never CA/hostname/discovery trust. Provisional mode exists
 * solely for explicitly initiated enrollment and grants no identity trust
 * until PAKE and both approvals complete. Both modes require valid P-256
 * self-signed host certificate and actual TLS CertificateVerify. */
internal class V2TlsTrust private constructor(pin:ByteArray?):X509TrustManager{
    private val expected=pin?.copyOf()
    companion object{
        fun production(pin:ByteArray):V2TlsTrust{require(pin.size==65&&pin[0]==4.toByte());return V2TlsTrust(pin)}
        fun enrollment()=V2TlsTrust(null)
        fun point(cert:X509Certificate):ByteArray {
            require(cert.encoded.size in 1..8192)
            cert.checkValidity()
            return V2KeyEncoding.point(cert.publicKey as? ECPublicKey?:error("P-256 TLS certificate required"))
        }
    }
    override fun checkClientTrusted(chain:Array<out X509Certificate>?,authType:String?):Unit=throw CertificateException("V2 client-only trust manager")
    override fun getAcceptedIssuers():Array<X509Certificate> = emptyArray()
    override fun checkServerTrusted(chain:Array<out X509Certificate>?,authType:String?){
        try{
            require(chain?.size==1);val cert=chain!!.single();val p=point(cert)
            require(cert.subjectX500Principal==cert.issuerX500Principal)
            cert.verify(cert.publicKey)
            require(expected==null||p.contentEquals(expected))
        }catch(e:Exception){throw CertificateException("V2 host certificate rejected",e)}
    }
}
