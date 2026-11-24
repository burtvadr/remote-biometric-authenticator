package io.github.burtvadr.rba.session

import android.content.Context
import android.util.Log
import io.github.burtvadr.rba.protocol.Id
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64

/** Records a paired host. */
data class KnownHost(
    val hostId: Id,
    val keyId: String,
    val publicKeyBytes: ByteArray,
    /** The host's TLS certificate, pinned so a proxy cannot intercept. */
    val pinnedCertificate: X509Certificate?,
    val hostName: String,
    /** Bearer capability for a device-initiated unpair; never used to authenticate. */
    val revocationToken: ByteArray? = null,
) {
    // data class equality on ByteArray is reference equality, which would make two
    // records loaded from disk never compare equal to the one just paired. Every
    // caller here compares by id, but leaving a broken equals in a record type is the
    // kind of thing that bites later.
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is KnownHost) return false
        return hostId.toHex() == other.hostId.toHex() &&
            keyId == other.keyId &&
            publicKeyBytes.contentEquals(other.publicKeyBytes) &&
            hostName == other.hostName &&
            ((revocationToken == null && other.revocationToken == null) ||
                (revocationToken != null &&
                    other.revocationToken != null &&
                    revocationToken.contentEquals(other.revocationToken)))
    }

    override fun hashCode(): Int {
        var result = hostId.toHex().hashCode()
        result = 31 * result + keyId.hashCode()
        result = 31 * result + publicKeyBytes.contentHashCode()
        result = 31 * result + hostName.hashCode()
        result = 31 * result + (revocationToken?.contentHashCode() ?: 0)
        return result
    }
}

/**
 * The paired-host set, with no Android dependency.
 *
 * All the rules live here so they can be tested on a plain JVM. [HostStore] is only
 * load-and-save plumbing on top.
 *
 * A device pairs with more than one PC -- a laptop, a desktop, a VM -- so the set is
 * keyed by `host_id` and one host's record can never displace another's
 * (PROTOCOL §11.3).
 */
class HostRegistry(initial: List<KnownHost> = emptyList()) {

    private val byId = LinkedHashMap<String, KnownHost>().apply {
        // Later records win, matching the order a re-pairing arrives in.
        initial.forEach { put(it.hostId.toHex(), it) }
    }

    fun all(): List<KnownHost> = byId.values.toList()

    fun get(hostId: Id): KnownHost? = byId[hostId.toHex()]

    fun isPaired(hostId: Id): Boolean = byId.containsKey(hostId.toHex())

    /** Inserts or replaces one host, leaving every other host untouched. */
    fun put(host: KnownHost): HostRegistry = apply { byId[host.hostId.toHex()] = host }

    /**
     * Removes one host.
     *
     * Returns whether anything was removed, so a caller can tell the user "this PC was
     * forgotten" rather than silently doing nothing.
     */
    fun remove(hostId: Id): Boolean = byId.remove(hostId.toHex()) != null

    val size: Int get() = byId.size
}

/**
 * Persistent store of the hosts this device has paired with.
 *
 * This exists as its own class rather than a list on [AuthenticatorSession] because a
 * list in memory silently loses the second PC: the user pairs their desktop, the system
 * restarts the app, and the host is gone with no explanation and no way to tell it
 * apart from one that was revoked or factory-reset.
 *
 * Nothing here is a secret that would let an attacker authenticate -- a host record is
 * public material plus a certificate pin. It is still app-private, because a process
 * that could write a record could add a host of its own and then prompt the user to
 * approve it.
 */
class HostStore(context: Context) {

    private val prefs = context.applicationContext
        .getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun load(): HostRegistry {
        val blob = prefs.getString(KEY_HOSTS, null)
            ?: return HostRegistry()
        return runCatching { HostRegistry(HostCodec.decodeAll(blob)) }.getOrElse { e ->
            // A store that cannot be parsed is treated as empty rather than crashing the
            // app: the user can re-pair. Refusing to start would leave them unable to
            // authenticate at all, with no way to diagnose it.
            Log.w(TAG, "cannot read the paired-host store; treating it as empty", e)
            HostRegistry()
        }
    }

    @Synchronized
    fun save(registry: HostRegistry) {
        prefs.edit().putString(KEY_HOSTS, HostCodec.encodeAll(registry.all())).apply()
    }

    fun all(): List<KnownHost> = load().all()

    fun get(hostId: Id): KnownHost? = load().get(hostId)

    fun isPaired(hostId: Id): Boolean = load().isPaired(hostId)

    /** Inserts or replaces one host, leaving every other host untouched. */
    @Synchronized
    fun put(host: KnownHost) = save(load().put(host))

    /** Pairing may acknowledge only after the pin and credential are on disk. */
    @Synchronized
    fun putDurably(host: KnownHost): Boolean {
        val previous = prefs.getString(KEY_HOSTS, null)
        val next = HostCodec.encodeAll(load().put(host).all())
        if (prefs.edit().putString(KEY_HOSTS, next).commit()) return true
        // SharedPreferences can update its in-memory view even when disk I/O
        // fails. Restore the previous view and never acknowledge this attempt.
        val restore = prefs.edit()
        if (previous == null) restore.remove(KEY_HOSTS) else restore.putString(KEY_HOSTS, previous)
        restore.commit()
        return false
    }

    /** Forgets one host. Returns whether it was actually paired. */
    @Synchronized
    fun remove(hostId: Id): Boolean {
        val current = load()
        if (!current.remove(hostId)) return false
        save(current)
        return true
    }

    @Synchronized
    fun clear() = prefs.edit().remove(KEY_HOSTS).apply()

    private companion object {
        const val TAG = "HostStore"
        const val PREFS = "rba-hosts"
        // Version in the key, so a future format is detected rather than misparsed.
        const val KEY_HOSTS = "hosts_v1"
    }
}

/**
 * Encoding for [KnownHost]: one record per line, fields separated by a unit separator.
 *
 * Hand-rolled rather than pulled from a serialization library, for the same reason the
 * rest of the protocol is: this is a security-relevant record, and the fewer
 * third-party behaviours it passes through, the better.
 */
internal object HostCodec {

    fun encodeAll(hosts: List<KnownHost>): String =
        hosts.joinToString(separator = "\n") { encode(it) }

    fun decodeAll(blob: String): List<KnownHost> =
        blob.lineSequence()
            .filter { it.isNotBlank() }
            .map { decode(it) }
            .toList()

    private fun encode(host: KnownHost): String = listOf(
        host.hostId.toHex(),
        host.keyId,
        b64(host.publicKeyBytes),
        host.pinnedCertificate?.let { b64(it.encoded) } ?: NO_CERT,
        // The label is operator-visible text and may contain anything, including the
        // separators below, so it is base64url encoded like the binary fields.
        b64url(host.hostName.toByteArray(Charsets.UTF_8)),
        host.revocationToken?.let { b64(it) } ?: NO_CERT,
    ).joinToString(separator = FIELD)

    private fun decode(line: String): KnownHost {
        val parts = line.split(FIELD)
        require(parts.size == 5 || parts.size == 6) {
            "a host record needs 5 or 6 fields, got ${parts.size}"
        }
        val publicKey = Base64.getDecoder().decode(parts[2])
        require(publicKey.size == PUBLIC_KEY_LEN) {
            "a host public key must be $PUBLIC_KEY_LEN bytes, got ${publicKey.size}"
        }
        val cert = if (parts[3] == NO_CERT) {
            null
        } else {
            CertificateFactory.getInstance("X.509")
                .generateCertificate(ByteArrayInputStream(Base64.getDecoder().decode(parts[3])))
                as X509Certificate
        }
        val revocationToken = if (parts.size < 6 || parts[5] == NO_CERT) {
            null
        } else {
            Base64.getDecoder().decode(parts[5]).also {
                require(it.size == REVOCATION_TOKEN_LEN) {
                    "a revocation token must be $REVOCATION_TOKEN_LEN bytes"
                }
            }
        }
        return KnownHost(
            hostId = Id.fromHex(parts[0]),
            keyId = parts[1],
            publicKeyBytes = publicKey,
            pinnedCertificate = cert,
            hostName = String(Base64.getUrlDecoder().decode(parts[4]), Charsets.UTF_8),
            revocationToken = revocationToken,
        )
    }

    private fun b64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)
    private fun b64url(bytes: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    /**
     * ASCII unit separator, between the fields of a record.
     *
     * It cannot occur in base64, in base64url, or in a hex id, so no value this codec
     * writes can forge an extra field. That matters because the decoder splits on it: a
     * separator that could appear inside a value would let operator-typed text smuggle
     * fields into a record.
     *
     * Written as an escape rather than a literal control character, which is invisible
     * in an editor and trivially lost to a copy-paste.
     */
    private const val FIELD = "\u001F"
    private const val NO_CERT = "-"
    private const val PUBLIC_KEY_LEN = 65
    private const val REVOCATION_TOKEN_LEN = 32
}