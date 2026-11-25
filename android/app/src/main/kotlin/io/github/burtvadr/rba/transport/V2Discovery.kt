package io.github.burtvadr.rba.transport

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.net.wifi.WifiManager
import android.util.Log
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
    private const val TAG = "RbaV2Discovery"
    private val scanLock=Mutex()
    const val SERVICE_TYPE = "_rba-v2._tcp."
    @Suppress("DEPRECATION")
    suspend fun scan(context: Context): List<V2DiscoveryHint> = scanLock.withLock {
        val nsd = context.getSystemService(Context.NSD_SERVICE) as NsdManager
        val queue = Channel<NsdServiceInfo>(16)
        val hints = linkedSetOf<V2DiscoveryHint>()
        val listener = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(serviceType: String?) { Log.d(TAG,"Discovery started") }
            override fun onDiscoveryStopped(serviceType: String?) { queue.close() }
            override fun onStartDiscoveryFailed(serviceType: String?, errorCode: Int) { Log.w(TAG,"Discovery start failed: $errorCode"); queue.close() }
            override fun onStopDiscoveryFailed(serviceType: String?, errorCode: Int) { Log.w(TAG,"Discovery stop failed: $errorCode"); queue.close() }
            override fun onServiceFound(info: NsdServiceInfo) {
                if (info.serviceType?.trimEnd('.')?.removeSuffix(".local") == SERVICE_TYPE.trimEnd('.')) queue.trySend(info)
            }
            override fun onServiceLost(info: NsdServiceInfo?) = Unit // hints expire at scan end; no trust/liveness claim
        }
        var multicastLock: WifiManager.MulticastLock? = null
        try {
            // The original HostLink acquired this lock. Older Android NSD
            // stacks require it; background scans may also need it. Hold it
            // only for this bounded scan, never for the lifetime of the app.
            try {
                val wifi = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
                multicastLock = wifi?.createMulticastLock("rba-v2-mdns")
                multicastLock?.setReferenceCounted(false)
                multicastLock?.acquire()
            } catch (e: SecurityException) {
                Log.w(TAG,"Multicast lock denied; attempting platform NSD")
            }
            nsd.discoverServices(SERVICE_TYPE,NsdManager.PROTOCOL_DNS_SD,listener)
            withTimeoutOrNull(5000L) {
                while (hints.size < 16) {
                    val info = queue.receiveCatching().getOrNull() ?: break
                    // A timed-out resolution ends the entire scan. Do not issue
                    // another resolution concurrently with an uncancellable one.
                    val resolved = withTimeoutOrNull(1500L) { resolve(nsd,info) }
                    if (resolved == null) { Log.w(TAG,"Service resolution timed out"); break }
                    val result = resolved.info ?: continue
                    val hint = V2DiscoveryHint.parse(result.host,result.port,result.attributes)
                    if (hint == null) Log.d(TAG,"Resolved service rejected by V2 hint validation")
                    else hints.add(hint)
                }
            }
        } finally {
            queue.cancel()
            runCatching { nsd.stopServiceDiscovery(listener) }
            runCatching { multicastLock?.let { if (it.isHeld) it.release() } }
                .onFailure { Log.w(TAG,"Multicast lock release failed") }
            Log.d(TAG,"Scan completed: ${hints.size} valid hints")
        }
        hints.toList()
    }
    private data class Resolution(val info:NsdServiceInfo?)
    @Suppress("DEPRECATION")
    private suspend fun resolve(nsd:NsdManager,info:NsdServiceInfo):Resolution = suspendCancellableCoroutine { c ->
        val listener = object:NsdManager.ResolveListener {
            override fun onResolveFailed(serviceInfo:NsdServiceInfo?,errorCode:Int) { Log.w(TAG,"Service resolution failed: $errorCode"); if(c.isActive)c.resume(Resolution(null)) }
            override fun onServiceResolved(serviceInfo:NsdServiceInfo) { if(c.isActive)c.resume(Resolution(serviceInfo)) }
        }
        try { nsd.resolveService(info,listener) }
        catch (_:IllegalArgumentException) { Log.w(TAG,"Service resolution rejected by platform"); if(c.isActive)c.resume(Resolution(null)) }
    }
}
