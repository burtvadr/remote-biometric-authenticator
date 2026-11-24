package io.github.burtvadr.rba.session

import android.content.Context
import android.net.wifi.WifiManager
import android.util.Log
import io.github.burtvadr.rba.protocol.Frame
import io.github.burtvadr.rba.protocol.Message
import io.github.burtvadr.rba.protocol.SessionHello
import io.github.burtvadr.rba.transport.WifiTransport
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import java.io.IOException
import java.security.cert.X509Certificate

/**
 * Finds a host over DNS-SD and keeps one protocol connection alive.
 *
 * This is the missing glue between the app's screens and the Wi-Fi adapter. It
 * deliberately makes no security decision of its own: pairing and authentication
 * are still decided by [AuthenticatorSession], and the transport only moves
 * frames. Its two non-obvious rules are:
 *
 * * A host whose certificate is pinned is only ever reached with that pin. An
 *   unpinned connection is used to bootstrap a first pairing, never to answer an
 *   authentication request for a host this device already knows.
 * * A lost connection is not a denial by itself, but a request that was on screen
 *   when the link dropped is: [AuthenticatorSession.transportLost] fails it closed.
 */
class HostLink(
    private val context: Context,
    private val session: AuthenticatorSession,
    private val scope: CoroutineScope,
) {

    private companion object {
        const val TAG = "HostLink"
        const val DISCOVERY_TIMEOUT_MS = 4_000L
        const val DISCOVERY_RETRY_MIN_MS = 2_000L

        /**
         * Discovery is only run while there is no live connection, so this backoff
         * is what the app costs while it waits for a host to come back.
         *
         * Before the first pairing the cap stays short: the operator has just run
         * `rba pair` and is waiting for the device to appear. Once a host
         * is paired a longer cap is safe: a healthy link is a blocked socket read
         * and costs nothing, and a host that returns is usually preceded by a
         * noticeable network event.
         */
        const val DISCOVERY_RETRY_MAX_UNPAIRED_MS = 5_000L
        const val DISCOVERY_RETRY_MAX_PAIRED_MS = 30_000L
        const val RECONNECT_DELAY_MS = 1_500L
    }

    @Volatile
    private var running = false

    private var loop: Job? = null

    /** Serialises the one live transport with start/stop. */
    private val linkLock = Any()

    private var active: WifiTransport? = null

    /**
     * Identifies the current start/stop cycle.
     *
     * A blocking socket read cannot be interrupted, so the coroutine from a previous
     * [start] can still be draining a connection after a quick stop/start. Without
     * this token it would see `running == true` again and resurrect itself, or its
     * cleanup would detach the transport that the new cycle just attached.
     */
    private var generation = 0

    private var multicastLock: WifiManager.MulticastLock? = null

    /** Begins discovery and reconnect handling. Safe to call more than once. */
    private var networkCallback: android.net.ConnectivityManager.NetworkCallback? = null

    fun start() {
        val token = synchronized(linkLock) {
            if (running) return
            running = true
            ++generation
            generation
        }
        acquireMulticastLock()
        session.setPairingSettledListener { closeActiveForReconnect() }
        // Re-resolve and reconnect when the network changes (Wi-Fi <-> VPN).
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE)
            as? android.net.ConnectivityManager
        val cb = object : android.net.ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: android.net.Network) {
                closeActiveForReconnect()
            }
            override fun onLost(network: android.net.Network) {
                closeActiveForReconnect()
            }
        }
        networkCallback = cb
        cm?.registerDefaultNetworkCallback(cb)
        loop = scope.launch(Dispatchers.IO) { runLoop(token) }
    }

    /** Stops discovery and closes the live connection. */
    fun stop(reason: String = "the connection to the host was stopped") {
        val hadTransport = synchronized(linkLock) {
            running = false
            ++generation
            val had = active != null
            active?.close()
            active = null
            had
        }
        loop?.cancel()
        loop = null
        networkCallback?.let { cb ->
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE)
                as? android.net.ConnectivityManager
            cm?.unregisterNetworkCallback(cb)
        }
        networkCallback = null
        session.setPairingSettledListener(null)
        releaseMulticastLock()
        session.detachTransport()
        if (hadTransport) session.transportLost(reason)
    }

    /**
     * Closes the unpinned pairing connection so the loop makes a fresh, pinned one.
     *
     * Runs on the operator's UI thread; the socket read is blocked in the link loop,
     * and closing the socket is what wakes it.
     */
    private fun closeActiveForReconnect() {
        synchronized(linkLock) {
            active?.close()
        }
    }

    /** True while [token] is still the current start/stop cycle. */
    private fun isCurrent(token: Int): Boolean = synchronized(linkLock) {
        running && generation == token
    }

    private suspend fun runLoop(token: Int) {
        var backoff = DISCOVERY_RETRY_MIN_MS
        while (isCurrent(token) && scope.isActive) {
            val candidates = discoverHosts()
            // Publish which paired hosts are currently visible on the network so
            // the UI can show reachability. This is a last-seen signal, not proof
            // of liveness.
            session.setDiscoveredKeyIds(candidates.mapNotNull { it.keyId }.toSet())
            if (candidates.isEmpty()) {
                delay(backoff)
                backoff = nextBackoff(backoff)
                continue
            }
            var served = false
            for (candidate in candidates) {
                if (!isCurrent(token)) break
                if (tryCandidate(token, candidate)) {
                    served = true
                    break
                }
            }
            if (!isCurrent(token)) break
            if (served) {
                backoff = DISCOVERY_RETRY_MIN_MS
                delay(RECONNECT_DELAY_MS)
            } else {
                delay(backoff)
                backoff = nextBackoff(backoff)
            }
        }
    }

    /** Grows the idle retry interval without ever stopping attempts entirely. */
    private fun nextBackoff(current: Long): Long {
        val cap = if (session.knownHosts().isEmpty()) {
            DISCOVERY_RETRY_MAX_UNPAIRED_MS
        } else {
            DISCOVERY_RETRY_MAX_PAIRED_MS
        }
        return (current * 2).coerceAtMost(cap)
    }

    /**
     * Tries, in order, every pinned host certificate and finally the bootstrap
     * (unpinned) connection. The order matters: a paired host must be reached with
     * its pin before any unpinned fallback is considered.
     */
    private suspend fun tryCandidate(token: Int, candidate: WifiTransport.Discovered): Boolean {
        val pinned = session.knownHosts().filter { it.pinnedCertificate != null }
        for (host in pinned) {
            if (!isCurrent(token)) return false
            if (connectAndServe(token, candidate, host.pinnedCertificate, host.hostId, host.keyId)) {
                return true
            }
        }
        if (!isCurrent(token)) return false
        // No pin matched. This is either a first pairing or a host whose certificate
        // changed. Pairing over an unpinned channel is authenticated by the code and
        // reciprocal MACs, so it is safe; answering authentication requests is not.
        return connectAndServe(token, candidate, null, null, null)
    }

    private suspend fun discoverHosts(): List<WifiTransport.Discovered> {
        val result = CompletableDeferred<List<WifiTransport.Discovered>>()
        val probe = WifiTransport(context, null)
        probe.discover(DISCOVERY_TIMEOUT_MS) { found ->
            result.complete(found)
        }
        return withTimeoutOrNull(DISCOVERY_TIMEOUT_MS + 3_000L) { result.await() }
            ?: emptyList()
    }

    /**
     * Connects, performs the session hello, then serves frames until the link ends.
     *
     * @return true when this candidate completed a recognised exchange and should
     * not be retried with the next certificate; false to let the caller try another.
     */
    private fun connectAndServe(
        token: Int,
        candidate: WifiTransport.Discovered,
        pinnedCertificate: X509Certificate?,
        expectedHostId: io.github.burtvadr.rba.protocol.Id?,
        expectedKeyId: String?,
    ): Boolean {
        val transport = WifiTransport(context, pinnedCertificate)
        val outbound = Channel<Frame>(Channel.UNLIMITED)
        var writer: Job? = null
        var attached = false
        var served = false

        try {
            transport.connect(candidate.host, candidate.port)
            val hello = when (val first = Message.fromFrame(transport.receive() ?: return false)) {
                is Message.SessionHelloMessage -> first.v
                else -> {
                    Log.w(TAG, "host opened with ${first.type}, not SESSION_HELLO")
                    return false
                }
            }

            if (!isCurrent(token)) return false

            if (expectedHostId != null) {
                if (hello.hostId != expectedHostId || hello.hostKeyId != expectedKeyId) {
                    // The certificate that made the connection may not be this host's.
                    // Try the next pinned record rather than trusting the channel.
                    Log.w(TAG, "pinned certificate did not match the host's SESSION_HELLO")
                    return false
                }
            }

            val pinnedLink = pinnedCertificate != null && expectedHostId != null
            val known = session.knownHosts().firstOrNull { it.hostId == hello.hostId }
            if (known != null && !pinnedLink && hello.hostKeyId != known.keyId) {
                // A known host id with a different key is either a reinstall or an
                // impostor. Neither is something to discover mid-connection.
                Log.w(TAG, "known host id presented an unexpected key")
                return false
            }
            if (known != null &&
                candidate.instanceName.isNotBlank() &&
                known.hostName != candidate.instanceName
            ) {
                // The mDNS label is display-only; the key/pin checks above are the
                // security decision. Rename so an old "linux-host" record picks up
                // the machine's real hostname without requiring a re-pair.
                session.updateHostName(hello.hostId, candidate.instanceName)
            }

            transport.send(
                Message.SessionHelloAckMessage(session.buildHelloAck(hello)).toFrame(),
            )

            synchronized(linkLock) {
                if (!running || generation != token) return false
                active = transport
            }

            writer = scope.launch(Dispatchers.IO) {
                for (frame in outbound) {
                    try {
                        transport.send(frame)
                    } catch (e: IOException) {
                        Log.i(TAG, "write failed: ${e.message}")
                        transport.close()
                        break
                    }
                }
            }
            session.attachTransport { frame -> outbound.trySend(frame).isSuccess }
            attached = true
            session.setConnectedHost(hello.hostId)

            // Set when a pairing has verified but the operator has not decided yet.
            // The bootstrap link stays open only to hold that context; no
            // authentication may be answered on it.
            var pairingParked = false

            while (isCurrent(token)) {
                val frame = transport.receive() ?: break
                when (val message = Message.fromFrame(frame)) {
                    is Message.PairingStartMessage -> {
                        if (message.v.hostId != hello.hostId || message.v.hostKeyId != hello.hostKeyId) {
                            // A pairing offer must name the host that opened this
                            // connection. Its session id is the independent pairing
                            // session, not the transport's SESSION_HELLO id.
                            Log.w(TAG, "pairing offer does not match the open session")
                            break
                        }
                        val certificate = transport.peerCertificate() ?: break
                        pairingParked = true
                        val outcome = session.handlePairingStart(message.v, candidate.instanceName, certificate)
                        if (outcome is SessionState.Failed) break
                        served = true
                    }

                    is Message.PairingChallengeMessage -> {
                        if (!pairingParked || session.handlePairingChallenge(message.v) is SessionState.Failed) break
                    }

                    is Message.PairingResultMessage -> {
                        if (!pairingParked || session.handlePairingResult(message.v) is SessionState.Failed) break
                    }

                    is Message.PairingConfirmedMessage -> {
                        if (!pairingParked || !session.handlePairingReceipt(message.v.sessionId)) break
                        served = true
                        break
                    }

                    is Message.AuthRequestMessage -> {
                        if (message.v.hostId != hello.hostId || message.v.hostKeyId != hello.hostKeyId) {
                            // The request must carry the identity that opened this
                            // connection. Its session id is per-request, not the
                            // transport's SESSION_HELLO id.
                            Log.w(TAG, "authentication request does not match the open session")
                            break
                        }
                        // The decision is made when the request arrives, not when
                        // the link was opened: a host can become paired (or start
                        // pairing) while this very connection is alive.
                        val knownNow = session.knownHosts().any { it.hostId == hello.hostId }
                        if (pairingParked || (!pinnedLink && knownNow)) {
                            // An unpinned link to a host this device already trusts
                            // could be a relay. Fail closed and let the pinned
                            // attempt win.
                            Log.w(TAG, "refusing an authentication request on an unpinned link")
                            break
                        }
                        session.offerRequest(message.v)
                    }

                    is Message.ErrorMessageEnvelope -> {
                        Log.i(TAG, "host error ${message.v.code}: ${message.v.message}")
                    }

                    else -> Log.w(TAG, "unexpected message ${message.type} from host")
                }
            }

            if (expectedHostId != null) {
                // A pinned host that accepted us is the right endpoint, even if the
                // link is now gone; reconnect rather than trying other certificates.
                served = true
            }
            return served
        } catch (e: Exception) {
            if (isCurrent(token)) {
                Log.i(TAG, "connection to ${candidate.host}:${candidate.port} ended: ${e.message}")
            }
            return false
        } finally {
            outbound.close()
            writer?.cancel()
            session.setConnectedHost(null)
            if (attached && isCurrent(token)) {
                session.detachTransport()
                session.transportLost("the connection to the host was lost")
            }
            synchronized(linkLock) {
                if (active === transport) active = null
            }
            transport.close()
        }
    }

    private fun acquireMulticastLock() {
        val wifi = context.applicationContext
            .getSystemService(Context.WIFI_SERVICE) as? WifiManager ?: return
        runCatching {
            val lock = wifi.createMulticastLock("rba-mdns").apply {
                setReferenceCounted(false)
                acquire()
            }
            multicastLock = lock
        }.onFailure { Log.w(TAG, "cannot acquire multicast lock: ${it.message}") }
    }

    private fun releaseMulticastLock() {
        runCatching { multicastLock?.release() }
        multicastLock = null
    }
}
