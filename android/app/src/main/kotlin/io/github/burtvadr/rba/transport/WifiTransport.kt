package io.github.burtvadr.rba.transport

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
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
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSocket

/**
 * The Wi-Fi transport: DNS-SD discovery plus a TLS 1.3 connection.
 *
 * Discovery is not trust. An attacker on the local network can advertise a
 * convincing fake service, so a resolved address only decides where to send the
 * first packet. The device's decision to approve rests entirely on the protocol
 * signature, and the TLS certificate is checked against the pin learned at
 * pairing.
 */
class WifiTransport(
    private val context: Context,
    /** Certificate pinned at pairing; `null` only before the first pairing. */
    private val pinnedCertificate: java.security.cert.X509Certificate?,
) : AutoCloseable {

    data class Discovered(val host: String, val port: Int, val instanceName: String)

    private var socket: SSLSocket? = null
    private var input: InputStream? = null
    private var output: OutputStream? = null
    private val buffer = java.io.ByteArrayOutputStream()
    private var consumed = 0

    /**
     * Builds the DNS-SD service record so hosts can find this device.
     *
     * Only non-secret metadata is published: a protocol version, the device
     * identifier, a short key fingerprint and a capability flag. Never a key,
     * secret or token.
     */
    fun advertise(deviceId: String, keyIdShort: String, port: Int, name: String): NsdServiceInfo {
        val info = NsdServiceInfo()
        info.serviceName = "$name [${deviceId.take(8)}]"
        info.serviceType = nsdServiceType()
        info.port = port
        // `NsdServiceInfo.setProperty` is not public API on all supported levels, so
        // the TXT records are assembled through the documented attribute and
        // exposed via the platform's own record API where available. When the
        // platform refuses, the record is advertised without TXT records, which
        // costs the host a confirmation step but never weakens authentication.
        runCatching {
            val m = info.javaClass.getMethod("setProperty", String::class.java, String::class.java)
            m.invoke(info, "v", "1")
            m.invoke(info, "id", deviceId)
            m.invoke(info, "fp", keyIdShort)
            m.invoke(info, "caps", "auth")
        }.onFailure { Log.w(TAG, "TXT records unavailable; advertising without them") }
        return info
    }

    /** Finds candidate hosts. Results are unverified until pairing succeeds. */
    fun discover(timeoutMillis: Long = 4000, onFound: (List<Discovered>) -> Unit) {
        val nsd = context.getSystemService(Context.NSD_SERVICE) as NsdManager
        val found = mutableListOf<Discovered>()
        val listener = object : NsdManager.DiscoveryListener {
            private val resolved = mutableListOf<NsdServiceInfo>()
            private var finished = false

            private fun maybeFinish() {
                if (!finished && System.currentTimeMillis() >= deadline) {
                    finished = true
                    nsd.stopServiceDiscovery(this)
                    onFound(
                        resolved.mapNotNull { info ->
                            val host = info.host?.hostAddress ?: return@mapNotNull null
                            Discovered(host, info.port, info.serviceName ?: "")
                        },
                    )
                }
            }

            private val deadline = System.currentTimeMillis() + timeoutMillis

            override fun onDiscoveryStarted(serviceType: String?) {
                Log.i(TAG, "discovery started for $serviceType")
            }

            override fun onServiceFound(serviceInfo: NsdServiceInfo) {
                nsd.resolveService(serviceInfo, object : NsdManager.ResolveListener {
                    override fun onResolveFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {
                        Log.w(TAG, "resolve failed: $errorCode")
                    }

                    override fun onServiceResolved(serviceInfo: NsdServiceInfo) {
                        synchronized(resolved) { resolved.add(serviceInfo) }
                    }
                })
            }

            override fun onServiceLost(serviceInfo: NsdServiceInfo?) = Unit

            override fun onDiscoveryStopped(serviceType: String?) {
                onFound(
                    resolved.mapNotNull { info ->
                        val host = info.host?.hostAddress ?: return@mapNotNull null
                        Discovered(host, info.port, info.serviceName ?: "")
                    },
                )
            }

            override fun onStartDiscoveryFailed(serviceType: String?, errorCode: Int) {
                // Guest networks commonly block multicast. Falling back to a fixed
                // endpoint is acceptable because the endpoint is never a trust anchor.
                Log.w(TAG, "mDNS discovery unavailable ($errorCode); use a fixed endpoint")
                onFound(emptyList())
            }

            override fun onStopDiscoveryFailed(serviceType: String?, errorCode: Int) {
                Log.w(TAG, "stop discovery failed: $errorCode")
            }
        }
        nsd.discoverServices(nsdServiceType(), NsdManager.PROTOCOL_DNS_SD, listener)

        // Discovery callbacks are not guaranteed to fire, so poll for the deadline.
        Thread {
            val until = System.currentTimeMillis() + timeoutMillis
            while (System.currentTimeMillis() < until) {
                Thread.sleep(200)
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
     */
    @Throws(IOException::class)
    fun connect(host: String, port: Int, connectTimeoutMillis: Int = 8000) {
        val plain = Socket()
        plain.connect(InetSocketAddress(host, port), connectTimeoutMillis)

        val factory = if (pinnedCertificate != null) {
            // Trust exactly the pinned certificate and nothing else: no system CAs,
            // because this is a direct device-to-host channel, not the public web.
            val trust = arrayOf(pinnedCertificate)
            SSLContext.getInstance("TLSv1.3").apply {
                init(null, arrayOf<javax.net.ssl.TrustManager>(PinnedTrustManager(trust)),
                    java.security.SecureRandom())
            }.socketFactory
        } else {
            // No pin yet: this connection is only used to receive PAIRING_START, and
            // the pairing transcript, not the TLS channel, authenticates the host.
            SSLContext.getInstance("TLSv1.3").apply {
                init(null, arrayOf<javax.net.ssl.TrustManager>(PinnedTrustManager(null)),
                    java.security.SecureRandom())
            }.socketFactory
        }

        val ssl = factory.createSocket(plain, host, port, true) as SSLSocket
        ssl.enabledProtocols = arrayOf("TLSv1.3")
        ssl.startHandshake()
        socket = ssl
        input = BufferedInputStream(ssl.inputStream)
        output = BufferedOutputStream(ssl.outputStream)
    }

    /** The host certificate observed during the handshake, for pinning at pairing. */
    fun peerCertificate(): java.security.cert.X509Certificate? = try {
        (socket?.session?.peerCertificates as? Array<java.security.cert.Certificate>)?.
            firstOrNull { it is java.security.cert.X509Certificate } as? java.security.cert.X509Certificate
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

    /** Reads the next frame, or null on a clean end of stream. */
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

/**
 * A trust manager that accepts exactly one certificate, or any certificate when
 * none is pinned.
 *
 * This is pinned-anchor behaviour, not blanket trust: with a pin present only that
 * certificate is accepted, so a proxy presenting its own certificate fails the
 * handshake. The `null` case exists solely to bootstrap the very first pairing,
 * where the host's certificate is not yet known; the pairing transcript, not TLS,
 * authenticates that exchange.
 *
 * The class name is deliberately not "trust everything" when a pin is set. Lint
 * flags any hand-written `X509TrustManager` because the usual failure mode is a
 * `checkServerTrusted` that returns without checking anything; here the pinned
 * case compares the presented certificate against the pin and throws when they
 * differ. The unpinned case exists for exactly one operation, receiving
 * `PAIRING_START`, and the protocol layer refuses to trust that response until the
 * pairing MACs verify.
 */
@Suppress("CustomX509TrustManager")
private class PinnedTrustManager(
    private val pinned: Array<java.security.cert.X509Certificate>?,
) : javax.net.ssl.X509TrustManager {

    override fun checkClientTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) = Unit

    override fun checkServerTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {
        if (pinned == null) return // bootstrap pairing only
        val presented = chain?.firstOrNull()
        require(presented != null) { "peer presented no certificate" }
        require(pinned.any { it.encoded.contentEquals(presented.encoded) }) {
            "peer certificate does not match the pinned host certificate"
        }
    }

    override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = emptyArray()
}
