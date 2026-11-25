package io.github.burtvadr.rba.transport

import org.junit.Assert.*
import org.junit.Test
import java.net.InetAddress
import java.security.MessageDigest

class V2DiscoveryHintTest {
    private val host = ByteArray(16) { 1 }
    private val point = ByteArray(65) { 7 }
    private fun hex(b:ByteArray)=b.joinToString(""){"%02x".format(it.toInt() and 255)}
    private val fields = mapOf("v" to "2", "id" to hex(host), "key" to hex(MessageDigest.getInstance("SHA-256").digest(point)), "role" to "auth")
    private fun hint(ip:String="192.168.1.5", port:Int=8765, data:Map<String,String> = fields) =
        V2DiscoveryHint.parse(InetAddress.getByName(ip),port,data.mapValues{it.value.toByteArray(Charsets.US_ASCII)})
    @Test fun privateV2HintsOnly(){
        assertNotNull(hint()); assertNotNull(hint("172.16.0.1")); assertNotNull(hint("10.0.0.2"))
        for (ip in listOf("127.0.0.1","0.0.0.0","8.8.8.8","100.85.36.40","172.32.1.1","::1")) assertNull(hint(ip))
        assertNull(hint(port=0));assertNull(hint(data=fields+ ("v" to "1")));assertNull(hint(data=fields+("id" to "00".repeat(16))))
    }
    @Test fun pinnedIdentityRouteIsExactAndUnambiguous(){
        val a=hint()!!;val b=hint("192.168.1.6")!!;val p=hint(port=8766,data=fields+mapOf("role" to "pair","attempt" to "02".repeat(16)))!!
        assertEquals(a,V2DiscoveryHint.enrolled(listOf(a,a,p),host,point));assertNull(V2DiscoveryHint.enrolled(listOf(a,b),host,point))
        assertNull(V2DiscoveryHint.enrolled(listOf(a),host,ByteArray(65){8}));assertNull(V2DiscoveryHint.enrolled(listOf(p),host,point))
        assertEquals(p,V2DiscoveryHint.pairing(listOf(a,p)));assertNull(V2DiscoveryHint.pairing(listOf(p,hint("192.168.1.6",8766,fields+mapOf("role" to "pair","attempt" to "02".repeat(16)))!!)))
    }
}
