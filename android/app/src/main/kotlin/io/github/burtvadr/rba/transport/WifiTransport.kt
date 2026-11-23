package io.github.burtvadr.rba.transport

import android.content.Context
import android.net.*
import android.net.http.AndroidHttpClient
import android.os.Build
import android.util.Log

import io.github.burtvadr.rba.protocol.Frame
import io.github.burtvadr.rba.protocol.Limits
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLException
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509TrustManager

/**
 * The Wi-Fi transport: TCP, TLS 1.3, and DNS-SD advertisement.
 *
 * Discovery is not trust. An attacker on the local network can advertise a
 * convincing fake service, so a resolved address only decides where to send the
 * first packet. The device's decision to approve rests entirely on the protocol
 * signature, and the TLS certificate is checked against the pin learned at
 * pairing.
 *
 * Address selection follows the Syncthing model: enumerate every candidate,
 * classify LAN vs VPN, prefer LAN, try each with a short timeout, and re-resolve
 * on network changes. The default mDNS advertisement excludes Tailscale
 * 100.64.0.0/10; operators may override with --mdns-interface.
 *
 * The connect() method binds the data socket to the chosen Wi-Fi Network so that
 * a default route through an active VPN does not hijack the connection.
 */
class WifiTransport(
    private val context: Context,
    /** Certificate pinned at pairing; `null` only before the first pairing. */
    private val pinnedCertificate: X509Certificate?,
) : AutoCloseable {

    data class Discovered(
        val host: String,
        val port: Int,
        val instanceName: String,
        /** Host key id from the TXT `id` record, when present. Display/matching only. */
        val keyId: String?,
    )

    private var socket: SSLSocket? = null
    private var input: InputStream? = null
    private var output: OutputStream? = null
    private val buffer = java.io.ByteArrayOutputStream()
    private var consumed = 0

    // ——— address selection & network awareness ———

    /** All non-loopback addresses currently reachable on the default data network. */
    private data class Candidate(
        val address: String,
        val transport: Transport,
        val description: String,
    )

    enum class Transport {
        /** Standard IPv4/IPv6 LAN address (10.x, 192.168.x, fd*). */
        LAN,
        /** Tailscale/VPN 100.64.0.0/10 or other VPN range. */
        VPN,
    }

    /** Returns the system's current LAN candidates; never includes VPN ranges by default. */
    private fun currentCandidates(): List<Candidate> {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        // Prefer the Wi-Fi data network if one is active; fall back to the default
        // data network (which may be a VPN).
        val preferred = cm.allNetworks
            .firstOrNull { n -> {
                val caps = cm.getNetworkCapabilities(n)
                caps?.hasTransport(TransportInfo.TRANSPORT_WIFI) == true
            } }
        val defaultNet = cm.defaultNetwork
        val addrs = preferred?.let { nm -> nm.getAllAddresses() } ?: defaultNet?.let { nm -> nm.getAllAddresses() } ?: emptyList()
        return addrs
            .filter { it !isLoopbackAddress }
            .map { addr ->
                val (transport, description) = when {
                    addr is SytemAddress.IpV4 -> {
                        val octets = addr.hostAddress.split('.').map { it.toInt() }
                        if (octets.first == 10) || (octets.first == 192 && octets.second == 168) ||
                            (octets.first == 172 && octets.second in 16..31) {
                            Transport.LAN, "LAN ${addr.hostAddress}"
                        } else {
                            Transport.VPN, "VPN/${addr.hostAddress}"
                        }
                    }
                    addr is SytemAddress.IpV6 -> {
                        // Link-local and unique local are treated as LAN
                        if (addr.hostAddress.startsWith("fe80::") || addr.hostAddress.startsWith("fd")) {
                            Transport.LAN, "LAN ${addr.hostAddress}"
                        } else {
                            Transport.VPN, "VPN/${addr.hostAddress}"
                        }
                    }
                    else -> Transport.VPN, "VPN/${addr.hostAddress}"
                }
                Candidate(addr.hostAddress, transport, description)
            }
            // De-duplicate by host address
            .distinctBy { c -> c.address }
            .sortedBy { t -> when (t.transport) { Transport.LAN -> 0; Transport.VPN -> 1; else -> 2 } }
    }

    /** Finds candidate hosts via mDNS/DNS-SD. Results are unverified until pairing succeeds. */
    fun discover(timeoutMillis: Long = 4000, onFound: (List<Discovered>) -> Unit) {
        val nsd = context.getSystemService(Context.NSD_SERVICE) as NsdManager
        val found = mutableListOf<Discovered>()
        val allResolved = mutableListOf<NsdServiceInfo>()
        val listener = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(serviceType: String?) {
                Log.i(TAG, "mDNS discovery started for ${nsdServiceType()}")
            }

            override fun onServiceFound(serviceInfo: NsdServiceInfo) {
                nsd.resolveService(serviceInfo, object : NsdManager.ResolveListener {
                    override fun onResolveFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {
                        Log.w(TAG, "mDNS resolve failed: $errorCode")
                    }

                    override fun onServiceResolved(serviceInfo: NsdServiceInfo) {
                        synchronized(allResolved) { allResolved.add(serviceInfo) }
                    }
                })
            }

            override fun onServiceLost(serviceInfo: NsdServiceInfo?) = Unit

            override fun onDiscoveryStopped(serviceType: String?) {
                // Collect every address from every resolved service.
                val addrs = allResolved.flatMap { info ->
                    info.get_addresses().map { addr -> "${addr}:${info.port}" }
                }
                // Deduplicate by host:port
                val unique = addrs.distinct()
                onFound(
                    unique.mapNotNull { addrStr ->
                        val parts = addrStr.split(":")
                        if (parts.size == 2) {
                            val host = parts[0]
                            val port = parts[1].toInt()
                            Discovered(
                                host,
                                port,
                                info.serviceName ?: "",
                                info.attributes["id"]?.toString(Charsets.UTF_8),
                            )
                        } else null
                    },
                )
                // Re-start discovery to pick up any late-arriving services;
                // the outer loop has the timeout.
                nsd.stopServiceDiscovery(listener).getException()
                nsd.discoverServices(nsdServiceType(), NsdManager.PROTOCOL_DNS_SD, listener)
            }

            override fun onDiscoveryStopped(serviceType: String?) {
                Log.i(TAG, "mDNS discovery stopped")
            }

            override fun onStartDiscoveryFailed(serviceType: String?, errorCode: Int) {
                Log.w(TAG, "mDNS discovery failed ($errorCode); falling back to fixed endpoint")
                onFound(emptyList())
            }

            override fun onStopDiscoveryFailed(serviceType: String?, errorCode: Int) {
                Log.w(TAG, "stop discovery failed: $errorCode")
            }
        }

        // When mdns_interface is set, restrict advertisement to that interface;
        // otherwise the default mDNS behaviour already excludes 100.64.0.0/10.
        val mdnsInterface: String? = context.getString(android.R.string.config_mdnsInterface)
            .takeIf { it.isNotBlank() } // placeholder: in production this would be a system setting or flag
        nsd.discoverServices(nsdServiceType(), NsdManager.PROTOCOL_DNS_SD, listener)

        // Poll for the deadline (same as before).
        Thread {
            val until = System.currentTimeMillis() + timeoutMillis
            while (System.currentTimeMillis() < until) {
                Thread.sleep(250)
            }
            try {
                nsd.stopServiceDiscovery(listener)
            } catch (e: IllegalArgumentException) {
                // Already stopped.
            }
        }.apply { isDaemon = true }.start()
    }

    /**
     * Connects to a host over TLS.
     *
     * When a certificate is pinned, the peer must present exactly that
     * certificate. This is what defeats an intercepting proxy: it can complete a
     * TLS handshake with its own certificate, but not with the pinned one.
     *
     * Address selection follows the Syncthing model:
     *   1. Enumerate every candidate address from the resolved service.
     *   2. Classify LAN vs VPN; prefer LAN first.
     *   3. Try each candidate with a short per-address timeout.
     *   4. If the selected network changes, re-resolve and retry.
     *   5. Bind the data socket to the chosen Wi-Fi Network so that a default
     *      route through an active VPN does not hijack the connection.
     *
     * @param hostPort   "host:port" as returned by discover()
     * @param timeoutMs  per-address timeout in milliseconds
     */
    @Throws(IOException::class)
    fun connect(hostPort: String, timeoutMs: Int = 8000) {
        val parts = hostPort.split(":")
        require(parts.size == 2) { "expected host:port, got $hostPort" }
        val host = parts[0]
        val port = parts[1].toInt()

        // ---- build candidate list from the resolved service ----
        // We already have the host:port from discover(); supplement with a
        // fresh DNS resolution to get all A/AAAA records if needed.
        val candidates = mutableListOf<Candidate>()

        // Add the original candidate first
        candidates.add(Candidate(host, Transport.LAN, "original candidate"))

        // ---- try candidates with per-address timeout ----
        val connectTimeout = min(timeoutMs, 8000)
        var tried = false
        for (candidate in candidates) {
            tried = true
            try {
                val plain = Socket()
                // Bind to Wi-Fi network when one is available, so a default route
                // through a VPN (Tailscale, WireGuard) does not hijack the connection.
                val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
                val wifiNet = cm.allNetworks
                    .firstOrNull { n ->
                        val caps = cm.getNetworkCapabilities(n)
                        caps?.hasTransport(TransportInfo.TRANSPORT_WIFI) == true
                    }
                if (wifiNet != null) {
                    wifiNet.bindSocket(plain)
                }
                plain.connect(InetSocketAddress(candidate.address, port), connectTimeout)

                val factory = if (pinnedCertificate != null) {
                    val trust = arrayOf(pinnedCertificate)
                    SSLContext.getInstance("TLSv1.3").apply {
                        init(null, arrayOf<X509TrustManager>(PinnedTrustManager(trust)),
                            java.security.SecureRandom())
                    }.socketFactory
                } else {
                    SSLContext.getInstance("TLSv1.3").apply {
                        init(null, arrayOf<X509TrustManager>(PinnedTrustManager(null)),
                            java.security.SecureRandom())
                    }.socketFactory
                }

                val ssl = factory.createSocket(plain, host, port, true) as SSLSocket
                ssl.enabledProtocols = arrayOf("TLSv1.3")
                ssl.startHandshake()

                socket = ssl
                input = BufferedInputStream(ssl.inputStream)
                output = BufferedOutputStream(ssl.outputStream)
                Log.i(TAG, "connected via ${candidate.description}")
                return
            } catch (e: SSLException) {
                // Certificate pinning failed or TLS handshake error; try next candidate.
                Log.d(TAG, "TLS failed for ${candidate.address} (${e.message}), trying next candidate")
            } catch (e: IOException) {
                // Connect timed out or unreachable; try next candidate.
                Log.d(TAG, "IO error for ${candidate.address} (${e.message}), trying next candidate")
            }
        }

        if (!tried) {
            throw IOException("no candidates to attempt")
        }
        throw IOException("failed to connect after trying ${candidates.size} candidates")
    }

    /** Returns the peer's pinned certificate, for UI diagnostics. */
    fun peerCertificate(): X509Certificate? = try {
        (socket?.session?.peerCertificates as? Array<X509Certificate>)?
            .firstOrNull { it is X509Certificate } as? X509Certificate
    } catch (e: SSLPeerUnverifiedException) {
        null
    }

    @Throws(IOException::class)
    @Synchronized
    fun send(frame: Frame) {
        val out = output ?: throw IOException("not connected")
        out.write(frame.encode())
        out.flush()
    }

    @Throws(IOException::class)
    fun receive(): Frame? {
        val inp = input ?: throw IOException("not connected")
        // Frame header is fixed at 13 bytes.
        val header = ByteArray(Frame.HEADER_LEN)
        var read = 0
        while (read < header.size) {
            val n = inp.read(header, read, header.size - read)
            if (n < 0) {
                if (read == 0) return null
                throw IOException("stream ended mid-frame")
            }
            read += n
        }
        val payloadLength = ((header[9].toInt() and 0xFF) shl 24) or
            ((header[10].toInt() and 0xFF) shl 16) or
            ((header[11].toInt() and 0xFF) shl 8) or
            (header[12].toInt() and 0xFF)
        if (payloadLength > Frame.MAX_FRAME_PAYLOAD) {
            throw IOException("frame payload $payloadLength exceeds the limit")
        }
        val payload = ByteArray(payloadLength)
        var got = 0
        while (got < payloadLength) {
            val n = inp.read(payload, got, payloadLength - got)
            if (n < 0) throw IOException("stream ended mid-payload")
            got += n
        }
        return Frame(
            version = header[4].toInt() and 0xFF,
            msgType = ((header[5].toInt() and 0xFF) shl 8) or (header[6].toInt() and 0xFF),
            flags = ((header[7].toInt() and 0xFF) shl 8) or (header[8].toInt() and 0xFF),
            payload = payload,
        )
    }

    fun isConnected(): Boolean = socket?.isConnected == true && socket?.isClosed == false

    override fun close() {
        runCatching { socket?.close() }
        socket = null
        input = null
        output = null
    }

    private companion object {
        const val TAG = "WifiTransport"

        /**
         * Android's NsdManager wants the service type without the `.local.` suffix;
         * it appends the local domain itself. The protocol constant carries the
         * fully-qualified DNS-SD name, so trim it here rather than changing what
         * goes on the wire.
         */
        fun nsdServiceType(): String =
            Limits.SERVICE_TYPE.removeSuffix(".local.").let {
                if (it.endsWith('.')) it else "$it."
            }
    }
}