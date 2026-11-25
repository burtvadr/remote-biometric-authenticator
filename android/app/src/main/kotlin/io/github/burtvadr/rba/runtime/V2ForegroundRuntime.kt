package io.github.burtvadr.rba.runtime

import android.content.Context
import io.github.burtvadr.rba.session.V2DeviceStore
import io.github.burtvadr.rba.transport.V2ConnectionOwner
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.sync.Mutex
import java.net.InetSocketAddress

/** Process-wide local routing boundary. No Intent extras may select or approve
 * an operation. The V2 candidate launcher is the only application entry point;
 * this is not a concurrent V1/V2 service. */
internal object V2ForegroundRuntime {
    private val mutex = Mutex()
    private var started = false
    enum class Operation { ENROLL, AUTHENTICATE, POLICY, RECOVER, REVOKE }
    private suspend fun <T> exclusive(work: suspend () -> T): T {
        check(mutex.tryLock()) { "An operation is already active" }
        try { return withContext(Dispatchers.IO) { work() } } finally { mutex.unlock() }
    }
    private suspend fun startup(context: Context) {
        if (!started) {
            V2ConnectionOwner.reclaimAtStartup(context)
            started = true
        }
    }
    suspend fun initialize(context: Context) = exclusive {
        check(!started)
        V2DeviceStore.initialize(context).use { }
        startup(context)
    }
    suspend fun inventory(context: Context) = exclusive {
        startup(context)
        V2DeviceStore.open(context).use { it.inventory() }
    }
    private fun decode(s: String): ByteArray {
        require(s.matches(Regex("[0-9a-f]{32}")) && s.any { it != '0' })
        return s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }
    /** Same exclusive startup/operation boundary as foreground work. A
     * background waiter cannot initialize storage, enroll or change policy. */
    suspend fun awaitAuthentication(context: Context, host:String, port:Int, credential:String,
                                    awaitUi:suspend (Long)->V2ConnectionOwner.Ui?):Boolean = exclusive {
        startup(context)
        require(host.isNotBlank() && host.length <= 253 && port in 1..65535)
        val address=InetSocketAddress(host,port);check(!address.isUnresolved)
        V2DeviceStore.open(context).use { store ->
            V2ConnectionOwner.authenticate(context,store,address,decode(credential),awaitUi)
        }
    }
    suspend fun operate(context: Context, host: String, port: Int, operation: Operation,
                        credential: String?, cleanup: List<String>, ui: V2ConnectionOwner.Ui): String = exclusive {
        startup(context)
        require(cleanup.isEmpty() || operation == Operation.ENROLL)
        V2DeviceStore.open(context).use { store ->
            // Local denial precedes even DNS resolution. Network failure must
            // never leave an explicitly revoked record usable.
            if (operation == Operation.REVOKE) {
                val id = decode(checkNotNull(credential))
                store.beginRevocation(id)
                if (store.revocationAcknowledged(id)) {
                    store.finishRevocationCleanup(id)
                    return@exclusive "Credential cleanup completed"
                }
            }
            require(host.isNotBlank() && host.length <= 253 && port in 1..65535)
            val address = InetSocketAddress(host, port)
            check(!address.isUnresolved)
            if (operation == Operation.ENROLL) {
                check(credential == null)
                V2ConnectionOwner.enroll(context, store, address, ui, cleanup.map(::decode))
                "Enrollment committed"
            } else {
                val id = decode(checkNotNull(credential))
                when (operation) {
                    Operation.AUTHENTICATE -> if (V2ConnectionOwner.authenticate(context, store, address, id, ui)) "Host reports authentication accepted" else "Authentication declined"
                    Operation.POLICY -> if (V2ConnectionOwner.synchronizePolicy(store, address, id, ui)) "Policy synchronized" else "Policy declined"
                    Operation.RECOVER -> { V2ConnectionOwner.recover(store, address, id); "Enrollment recovered" }
                    Operation.REVOKE -> { V2ConnectionOwner.revoke(store, address, id); "Credential revoked" }
                    Operation.ENROLL -> error("Unreachable")
                }
            }
        }
    }
}
