package io.github.burtvadr.rba.transport

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.coroutines.resume

/** Bounded, V2-only DNS-SD scan. No connection, enrollment or UI action is
 * triggered here. Resolve serially for Android versions with one outstanding
 * resolution. Cancellation closes discovery and ignores late callbacks. */
internal object V2Discovery {
    private val scanLock=Mutex()
    const val SERVICE_TYPE = "_rba-v2._tcp."
    @Suppress("DEPRECATION")
    suspend fun scan(context: Context): List<V2DiscoveryHint> = scanLock.withLock {
        val nsd = context.getSystemService(Context.NSD_SERVICE) as NsdManager
        val queue = Channel<NsdServiceInfo>(16)
        val hints = linkedSetOf<V2DiscoveryHint>()
        val listener = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(serviceType: String?) = Unit
            override fun onDiscoveryStopped(serviceType: String?) { queue.close() }
            override fun onStartDiscoveryFailed(serviceType: String?, errorCode: Int) { queue.close() }
            override fun onStopDiscoveryFailed(serviceType: String?, errorCode: Int) { queue.close() }
            override fun onServiceFound(info: NsdServiceInfo) {
                if (info.serviceType?.trimEnd('.')?.removeSuffix(".local") == SERVICE_TYPE.trimEnd('.')) queue.trySend(info)
            }
            override fun onServiceLost(info: NsdServiceInfo?) = Unit // hints expire at scan end; no trust/liveness claim
        }
        try {
            nsd.discoverServices(SERVICE_TYPE,NsdManager.PROTOCOL_DNS_SD,listener)
            withTimeoutOrNull(5000L) {
                while (hints.size < 16) {
                    val info = queue.receiveCatching().getOrNull() ?: break
                    // A timed-out resolution ends the entire scan. Do not issue
                    // another resolution concurrently with an uncancellable one.
                    val resolved = withTimeoutOrNull(1500L) { resolve(nsd,info) } ?: break
                    val result = resolved.info ?: continue
                    V2DiscoveryHint.parse(result.host,result.port,result.attributes)?.let { hints.add(it) }
                }
            }
        } finally {
            queue.cancel()
            runCatching { nsd.stopServiceDiscovery(listener) }
        }
        hints.toList()
    }
    private data class Resolution(val info:NsdServiceInfo?)
    @Suppress("DEPRECATION")
    private suspend fun resolve(nsd:NsdManager,info:NsdServiceInfo):Resolution = suspendCancellableCoroutine { c ->
        val listener = object:NsdManager.ResolveListener {
            override fun onResolveFailed(serviceInfo:NsdServiceInfo?,errorCode:Int) { if(c.isActive)c.resume(Resolution(null)) }
            override fun onServiceResolved(serviceInfo:NsdServiceInfo) { if(c.isActive)c.resume(Resolution(serviceInfo)) }
        }
        try { nsd.resolveService(info,listener) }
        catch (_:IllegalArgumentException) { if(c.isActive)c.resume(Resolution(null)) }
    }
}
