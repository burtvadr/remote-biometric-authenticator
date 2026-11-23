package io.github.burtvadr.rba.session

import android.content.Context
import io.github.burtvadr.rba.protocol.Id
import java.util.Base64

/**
 * Revocation tokens whose host has not been reached yet.
 *
 * The device always forgets a host locally. If the pinned link is down, the token
 * is kept here and included in the next pairing submit for that host. The host
 * then revokes the old record before it commits the new one.
 */
class PendingRevocations(context: Context) {
    private val prefs = context.applicationContext
        .getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun add(hostId: Id, token: ByteArray) {
        val existing = tokens(hostId).map { Base64.getEncoder().encodeToString(it) }.toMutableSet()
        existing += Base64.getEncoder().encodeToString(token)
        prefs.edit().putString(key(hostId), existing.joinToString(",")).apply()
    }

    fun tokens(hostId: Id): List<ByteArray> {
        val raw = prefs.getString(key(hostId), null) ?: return emptyList()
        return raw.split(',')
            .mapNotNull { encoded ->
                runCatching { Base64.getDecoder().decode(encoded) }
                    .getOrNull()
                    ?.takeIf { it.size == TOKEN_LEN }
            }
    }

    fun clear(hostId: Id) {
        prefs.edit().remove(key(hostId)).apply()
    }

    private fun key(hostId: Id) = "host_${hostId.toHex()}"

    private companion object {
        const val PREFS = "rba-pending-revocations"
        const val TOKEN_LEN = 32
    }
}
