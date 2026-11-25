package io.github.burtvadr.rba.transport

import java.net.Inet4Address
import java.net.InetAddress
import java.security.MessageDigest

/** Discovery is untrusted metadata. Only the enrolled TLS/session owner can
 * authenticate a host. A hint never creates a grant, key or pairing record. */
internal data class V2DiscoveryHint private constructor(
    val hostId: String, val keyHash: String, val role: Role,
    val address: String, val port: Int, val attempt: String, val label: String,
) {
    enum class Role { AUTH, PAIR }
    companion object {
        private val id = Regex("[0-9a-f]{32}")
        private val digest = Regex("[0-9a-f]{64}")
        private fun ascii(b: ByteArray?) = b?.takeIf { it.size <= 64 && it.all { x -> x.toInt() in 32..126 } }?.toString(Charsets.US_ASCII)
        private fun hex(b:ByteArray) = b.joinToString(""){"%02x".format(it.toInt() and 255)}
        fun parse(address: InetAddress?, port: Int, attributes: Map<String, ByteArray>): V2DiscoveryHint? {
            if (address !is Inet4Address || port !in 1..65535 || ascii(attributes["v"]) != "2") return null
            val ip = address.address.map { it.toInt() and 255 }
            if (!(ip[0] == 10 || ip[0] == 172 && ip[1] in 16..31 || ip[0] == 192 && ip[1] == 168)) return null
            val host = ascii(attributes["id"])?.takeIf { it.matches(id) && it.any { c -> c != '0' } } ?: return null
            val key = ascii(attributes["key"])?.takeIf { it.matches(digest) && it.any { c -> c != '0' } } ?: return null
            val role = when (ascii(attributes["role"])) { "auth" -> Role.AUTH; "pair" -> Role.PAIR; else -> return null }
            val attempt=ascii(attributes["attempt"]).orEmpty()
            if(role==Role.PAIR && (!attempt.matches(id)||attempt.all{it=='0'}))return null
            if(role==Role.AUTH && attempt.isNotEmpty())return null
            val label=ascii(attributes["name"])?.takeIf{it.length in 1..32 && it.all{c->c.isLetterOrDigit()||c in "-_ "} && it.isNotBlank()}?:"Host ${host.take(8)}"
            return V2DiscoveryHint(host,key,role,address.hostAddress ?: return null,port,attempt,label)
        }
        /** No silent choice between competing pairing listeners. This is a
         * route candidate, not approval; the enrollment UI remains mandatory. */
        fun pairing(hints: List<V2DiscoveryHint>): V2DiscoveryHint? = hints.filter { it.role == Role.PAIR }.distinct().singleOrNull()
        /** Match the locally persisted host id and public-key fingerprint.
         * DNS-SD can be spoofed; the existing V2 TLS pin and HELLO checks are
         * still mandatory, even for a unique exact match. */
        fun enrolled(hints: List<V2DiscoveryHint>, host: ByteArray, point: ByteArray): V2DiscoveryHint? {
            require(host.size == 16 && point.size == 65)
            val hostId = hex(host)
            val keyHash = hex(MessageDigest.getInstance("SHA-256").digest(point))
            return hints.filter { it.role == Role.AUTH && it.hostId == hostId && it.keyHash == keyHash }.distinct().singleOrNull()
        }
    }
}
