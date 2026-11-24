package io.github.burtvadr.rba.session

import android.content.Context
import io.github.burtvadr.rba.biometric.BiometricAvailability
import io.github.burtvadr.rba.biometric.BiometricOutcome
import io.github.burtvadr.rba.biometric.authenticateStrong
import io.github.burtvadr.rba.keystore.DeviceAuthKey
import io.github.burtvadr.rba.protocol.AuthRequest
import io.github.burtvadr.rba.protocol.AuthResponse
import io.github.burtvadr.rba.protocol.Challenge
import io.github.burtvadr.rba.protocol.CodeEntry
import io.github.burtvadr.rba.protocol.ErrorCode
import io.github.burtvadr.rba.protocol.Frame
import io.github.burtvadr.rba.protocol.Hex
import io.github.burtvadr.rba.protocol.Id
import io.github.burtvadr.rba.protocol.Limits
import io.github.burtvadr.rba.protocol.Message
import io.github.burtvadr.rba.protocol.PairingConfirmed
import io.github.burtvadr.rba.protocol.PairingResult
import io.github.burtvadr.rba.protocol.PairingChallenge
import io.github.burtvadr.rba.protocol.PairingProof
import java.nio.ByteBuffer
import io.github.burtvadr.rba.protocol.PairingStart
import io.github.burtvadr.rba.protocol.PairingSubmit
import io.github.burtvadr.rba.protocol.ProtocolException
import io.github.burtvadr.rba.protocol.SessionHello
import io.github.burtvadr.rba.protocol.SessionHelloAck
import io.github.burtvadr.rba.protocol.Unpair
import io.github.burtvadr.rba.protocol.sha256
import io.github.burtvadr.rba.transport.BleTransport
import io.github.burtvadr.rba.transport.WifiTransport
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import java.io.IOException
import java.security.cert.X509Certificate
import java.util.concurrent.Executor

/**
 * One place where a request can be shown, decided and answered.
 *
 * The ordering here is the security property, and it is not negotiable:
 *
 * 1. The request is parsed and validated.
 * 2. Its **signed** context is displayed to the operator.
 * 3. The operator is asked.
 * 4. A strong biometric check runs.
 * 5. Only then is the Keystore key asked to sign.
 *
 * Nothing is signed before the operator has seen the context, and nothing is sent
 * unless the signature succeeded.
 */
sealed interface SessionState {
    data object Idle : SessionState

    /**
     * `code_entry = device`: the host displays the code and the device will ask
     * the operator to type it after the host's MAC verifies.
     *
     * The derived code is deliberately absent: the device must never display it.
     */
    data class PairingAwaitingCode(val hostName: String) : SessionState

    /**
     * `code_entry = host`: the device displays the code and the operator types it
     * into the host terminal.
     */
    data class PairingAwaitingHostCode(val hostName: String, val code: String) : SessionState

    /**
     * `code_entry = device`: the host proved the transcript and now the operator
     * must type the code shown on the host screen. A bare tap is not enough.
     */
    data class PairingAwaitingConfirmation(val hostName: String) : SessionState

    /**
     * `code_entry = host`: the host proved the transcript after typing the code
     * from this screen. The operator still has to approve this host explicitly.
     */
    data class PairingAwaitingApproval(val hostName: String, val code: String) : SessionState

    data class PairingFinalizing(val hostName: String) : SessionState

    data class PairingConfirmed(val hostName: String) : SessionState

    /**
     * A request is on screen, waiting for the operator.
     *
     * [hostName] and [hostKeyId] come from the locally stored paired-host record
     * and the signed host id, not from the unsigned display label in the request.
     */
    data class AwaitingApproval(
        val request: AuthRequest,
        val hostName: String,
        val hostKeyId: String,
    ) : SessionState

    /** A biometric prompt is in front of the operator. */
    data class AwaitingBiometric(
        val request: AuthRequest,
        val hostName: String,
        val hostKeyId: String,
    ) : SessionState

    /** Signed and sent. */
    data class Approved(
        val request: AuthRequest,
        val hostName: String,
        val hostKeyId: String,
    ) : SessionState

    /** Denied, with the reason shown to the operator. */
    data class Denied(val requestId: String, val reason: String) : SessionState

    data class Failed(val message: String) : SessionState
}

/**
 * Drives one connection to a host.
 *
 * Transport-independent by construction: it works over [`WifiTransport`] or
 * [`BleTransport`], and which one is in use cannot change whether a request is
 * approved.
 */
class AuthenticatorSession(
    private val context: Context,
    private val key: DeviceAuthKey,
    val deviceId: Id,
    val deviceName: String,
    /** Paired hosts, persisted. A device pairs with more than one PC. */
    private val hosts: HostStore,
    /** Scope for background work; supplied by the activity's lifecycle. */
    @Suppress("unused") private val scope: CoroutineScope,
) {

    private val pendingRevocations = PendingRevocations(context)

    private data class PendingPairing(
        val offer: PairingStart,
        val hostName: String,
        val certificate: X509Certificate,
        val deviceKey: ByteArray,
        var exchange: NativeEnrollment.Exchange? = null,
        var proof: ByteArray? = null,
        var proofSent: Boolean = false,
    )
    private var pendingPairing: PendingPairing? = null
    private data class ConfirmedPairing(val sessionId: Id, val host: KnownHost, val hostName: String)
    private var pendingAcknowledgement: ConfirmedPairing? = null

    private fun clearPairing() {
        pendingPairing?.exchange?.close()
        pendingPairing?.proof?.fill(0)
        pendingPairing = null
    }

    /** Clears a parked confirmation that the operator never settles. */
    private var confirmationTimeout: Job? = null

    /**
     * Invoked when the operator settles pairing (confirms or rejects), so the
     * transport reconnects pinned or drops the rejected link.
     */
    @Volatile
    private var pairingSettledListener: (() -> Unit)? = null

    private val _state = MutableStateFlow<SessionState>(SessionState.Idle)
    val state: StateFlow<SessionState> = _state

    /** Paired hosts, observable so the overview updates after an unpair. */
    private val _hosts = MutableStateFlow<List<KnownHost>>(hosts.all())
    val knownHostsFlow: StateFlow<List<KnownHost>> = _hosts

    /**
     * The host the idle link is currently serving, or null when there is no link.
     * Written by [HostLink]; read by the UI to show which host is connected.
     */
    private val _connectedHostId = MutableStateFlow<Id?>(null)
    val connectedHostId: StateFlow<Id?> = _connectedHostId

    /**
     * Host key ids seen in the most recent mDNS discovery. This is a "last seen"
     * signal, not a liveness probe: a host that is up but not advertising (guest
     * network, multicast filtered) will not appear here. Matching/display only.
     */
    private val _discoveredKeyIds = MutableStateFlow<Set<String>>(emptySet())
    val discoveredKeyIds: StateFlow<Set<String>> = _discoveredKeyIds

    fun setConnectedHost(id: Id?) {
        _connectedHostId.value = id
    }

    fun setDiscoveredKeyIds(ids: Set<String>) {
        _discoveredKeyIds.value = ids
    }

    /**
     * Hosts this device has paired with, read through to [HostStore].
     *
     * Not a local list: the user pairs a second PC, the app is restarted by the system
     * at some point, and an in-memory list would silently forget the first one. The
     * forgotten host is indistinguishable from a revoked one, which is the kind of
     * problem that arrives as "the app sometimes stops working".
     */

    /**
     * The request the operator is currently deciding, if any.
     *
     * Held explicitly rather than inferred from the UI so the session owns the
     * decision, not the composable.
     */
    private var pendingRequest: AuthRequest? = null

    /**
     * A request may never be signed on the back of a biometric success that
     * belonged to a different request.
     *
     * This is bound when the operator approves, and cleared as soon as a signature
     * is produced or the request is abandoned. It is the session-level guard
     * against a stale biometric result authorising a later request.
     */
    private var approvedRequestId: String? = null

    /**
     * The signature prepared for the request whose biometric prompt is up.
     *
     * Keystore authorises the exact `Signature` object bound to the prompt, so this
     * is the only path from a successful biometric to an approval. It is cleared on
     * every denial, link loss or stale callback so a late result cannot sign a
     * request the operator no longer has on screen.
     */
    private var signingOperation: DeviceAuthKey.SigningOperation? = null

    /** Whether this device can satisfy the strong-biometric policy at all. */
    @Volatile
    private var strongBiometricAvailable: Boolean = false

    init {
        key.ensureKey()
    }

    /**
     * Records a completed pairing, replacing any earlier record for the same host.
     *
     * Only ever called once the transcript has completed and the reciprocal MAC has
     * verified, so a failed pairing cannot leave a usable record behind.
     */
    fun addKnownHost(host: KnownHost) {
        hosts.put(host)
        _hosts.value = hosts.all()
    }

    fun knownHosts(): List<KnownHost> = _hosts.value

    /** Updates only the operator-visible label; never the key or pin. */
    fun updateHostName(hostId: io.github.burtvadr.rba.protocol.Id, name: String) {
        val host = hosts.get(hostId) ?: return
        if (name.isBlank() || host.hostName == name) return
        hosts.put(host.copy(hostName = name))
        _hosts.value = hosts.all()
    }

    /**
     * Installs the callback that runs once the operator settles a pairing.
     *
     * The transport uses it to drop the unpinned bootstrap connection and reconnect
     * with the new pin (or close the link after a rejection). An authentication
     * request must never be answerable on the unpinned link that happened to carry
     * the pairing exchange.
     */
    fun setPairingSettledListener(listener: (() -> Unit)?) {
        pairingSettledListener = listener
    }

    /**
     * Forgets one host. Returns whether it was actually paired.
     *
     * The device's local record goes first. If a pinned link is open, it also sends
     * the host the bearer token so the host can revoke its side. If the host is
     * unreachable, the token is kept for the next pairing submit.
     */
    fun forgetHost(hostId: io.github.burtvadr.rba.protocol.Id): Boolean {
        val host = hosts.get(hostId) ?: return false
        host.revocationToken?.let { token ->
            pendingRevocations.add(hostId, token)
            if (transportSink != null) {
                send(Message.UnpairMessage(Unpair(token)).toFrame())
            }
        }
        val removed = hosts.remove(hostId)
        if (removed) {
            _hosts.value = hosts.all()
        }
        return removed
    }

    /** Records whether a strong biometric is enrolled, for policy decisions. */
    fun setAvailability(available: Boolean) {
        strongBiometricAvailable = available
    }

    /** The request awaiting the operator's decision, if any. */
    fun pendingRequest(): AuthRequest? = pendingRequest

    /**
     * Called when the operator declines. No prompt is shown and nothing is signed.
     */
    fun declinePending() {
        pendingRequest?.let { reject(it) }
        pendingRequest = null
        approvedRequestId = null
        signingOperation = null
    }

    /**
     * Entry point for the transport layer: a request arrived.
     *
     * The session validates it and, only if it may be shown, moves to
     * [SessionState.AwaitingApproval]. Everything else is refused without
     * troubling the operator.
     */
    fun offerRequest(request: AuthRequest) {
        val now = System.currentTimeMillis() / 1000
        // Unpairing must take effect on an already-open pinned link too. The link
        // was authenticated when it opened; the host record can disappear later.
        if (hosts.get(request.hostId) == null) {
            send(
                Message.AuthRejectMessage(
                    io.github.burtvadr.rba.protocol.AuthReject(
                        request.requestId,
                        ErrorCode.NOT_PAIRED.code,
                    ),
                ).toFrame(),
            )
            _state.value = SessionState.Failed("request from an unpaired host")
            return
        }
        // One decision at a time. A second request must not replace the one whose
        // signature is already bound to a visible prompt.
        if (pendingRequest != null || signingOperation != null) {
            send(
                Message.AuthRejectMessage(
                    io.github.burtvadr.rba.protocol.AuthReject(
                        request.requestId,
                        ErrorCode.RATE_LIMITED.code,
                    ),
                ).toFrame(),
            )
            return
        }
        if (request.expiresAt < now) {
            // The host has already stopped waiting. Showing a prompt would train the
            // operator to approve requests that cannot succeed.
            send(
                Message.AuthRejectMessage(
                    io.github.burtvadr.rba.protocol.AuthReject(
                        request.requestId,
                        ErrorCode.EXPIRED.code,
                    ),
                ).toFrame(),
            )
            _state.value = SessionState.Denied(
                request.requestId.toHex(),
                "this request has already expired",
            )
            return
        }
        if (!strongBiometricAvailable) {
            // Refuse up front: a prompt that cannot succeed is just a way to train
            // the operator to tap through dialogs.
            send(
                Message.AuthRejectMessage(
                    io.github.burtvadr.rba.protocol.AuthReject(
                        request.requestId,
                        ErrorCode.BIOMETRIC_FAILED.code,
                    ),
                ).toFrame(),
            )
            _state.value = SessionState.Denied(
                request.requestId.toHex(),
                "this device has no strong biometric enrolled",
            )
            return
        }
        requestApproval(request)
    }

    /**
     * Answers the host's `SESSION_HELLO`.
     *
     * The device nonce is fresh for every connection and is only used for this
     * session; it never becomes long-lived state.
     */
    fun buildHelloAck(hello: SessionHello): SessionHelloAck {
        val publicKey = key.publicKeyBytes()
            ?: throw ProtocolException(ErrorCode.INTERNAL, "device key is unavailable")
        val nonce = ByteArray(Limits.CHALLENGE_LEN).also {
            java.security.SecureRandom().nextBytes(it)
        }
        return SessionHelloAck(
            deviceId = deviceId,
            deviceKeyId = Hex.encode(sha256(publicKey)),
            deviceNonce = nonce,
            sessionId = hello.sessionId,
        )
    }

    /** Installs the sink for the currently connected transport. */
    @Synchronized
    fun attachTransport(sink: (Frame) -> Boolean) {
        transportSink = sink
    }

    @Synchronized
    fun detachTransport() {
        transportSink = null
    }

    /**
     * Called by the transport when the link goes away.
     *
     * An unanswered request is a denial: the host has already stopped waiting, and
     * nothing may be left on screen that could later be approved against a dead
     * session.
     */
    @Synchronized
    fun transportLost(reason: String) {
        transportSink = null
        val pairing = pendingPairing != null || pendingAcknowledgement != null
        clearPairing()
        val request = pendingRequest
        pendingRequest = null
        approvedRequestId = null
        signingOperation = null
        pendingAcknowledgement = null
        confirmationTimeout?.cancel()
        confirmationTimeout = null
        if (request != null) _state.value = SessionState.Denied(request.requestId.toHex(), reason)
        else if (pairing) _state.value = SessionState.Failed(reason)
    }

    /** Installed by the active transport adapter. */
    @Volatile
    private var transportSink: ((Frame) -> Boolean)? = null

    // -----------------------------------------------------------------------
    // Pairing
    // -----------------------------------------------------------------------

    /** Begin a single exchange on the actual TLS connection, never a claimed pin. */
    @Synchronized
    fun handlePairingStart(start: PairingStart, hostName: String, certificate: X509Certificate): SessionState {
        if (pendingPairing != null || pendingAcknowledgement != null) return abortPairing("another pairing is active")
        return try {
            val now = System.currentTimeMillis() / 1000
            require(start.expiresAt > now && start.expiresAt <= now + Limits.PAIRING_TTL)
            require(Hex.encode(sha256(start.hostPublicKey)) == start.hostKeyId)
            hosts.get(start.hostId)?.let { require(it.publicKeyBytes.contentEquals(start.hostPublicKey)) }
            val publicKey = key.publicKeyBytes() ?: return abortPairing("device key unavailable")
            val pending = PendingPairing(start, hostName.ifBlank { "Host" }, certificate, publicKey)
            pendingPairing = pending
            confirmationTimeout?.cancel()
            confirmationTimeout = scope.launch {
                delay((start.expiresAt - now) * 1000L)
                synchronized(this@AuthenticatorSession) {
                    if (pendingPairing === pending) abortPairing("pairing expired")
                }
            }
            if (start.codeEntry == CodeEntry.DEVICE) {
                _state.value = SessionState.PairingAwaitingConfirmation(pending.hostName)
            } else {
                val code = NativeEnrollment.generateCode()
                val display = String(code, Charsets.US_ASCII)
                startExchange(pending, code)
                _state.value = SessionState.PairingAwaitingHostCode(pending.hostName, display)
            }
            _state.value
        } catch (_: Exception) { abortPairing("could not start secure enrollment") }
          catch (_: LinkageError) { abortPairing("native enrollment library unavailable") }
    }

    private fun startExchange(p: PendingPairing, code: ByteArray) {
        check(p.exchange == null && p.proof == null && !p.proofSent)
        val context = ByteBuffer.allocate(219)
            .put(p.offer.sessionId.bytes).put(p.offer.hostId.bytes).put(deviceId.bytes)
            .put(p.offer.hostPublicKey).put(p.deviceKey).put(sha256(p.certificate.encoded))
            .putLong(p.offer.expiresAt).put(if (p.offer.codeEntry == CodeEntry.DEVICE) 0.toByte() else 1.toByte()).array()
        val exchange = NativeEnrollment.Exchange.start(code, context)
        p.exchange = exchange
        val submit = PairingSubmit(p.offer.sessionId, deviceId, deviceName, p.deviceKey, Hex.encode(sha256(p.deviceKey)), exchange.share)
        check(transportSink?.invoke(Message.PairingSubmitMessage(submit).toFrame()) == true)
    }

    @Synchronized
    fun handlePairingChallenge(challenge: PairingChallenge): SessionState {
        val p = pendingPairing ?: return abortPairing("unexpected enrollment challenge")
        return try {
            require(challenge.sessionId == p.offer.sessionId && p.offer.expiresAt > System.currentTimeMillis() / 1000)
            val exchange = p.exchange ?: return abortPairing("no active exchange")
            p.exchange = null
            p.proof = exchange.confirm(challenge.share, challenge.confirmation)
            if (p.offer.codeEntry == CodeEntry.DEVICE) sendProof(p)
            else {
                // The displayed password is no longer needed; the second UI
                // gate approves the authenticated host, not another code.
                _state.value = SessionState.PairingAwaitingApproval(p.hostName, "")
            }
            _state.value
        } catch (_: Exception) { abortPairing("pairing confirmation failed") }
    }

    private fun sendProof(p: PendingPairing) {
        val proof = p.proof ?: error("host not verified")
        check(!p.proofSent)
        p.proof = null
        p.proofSent = true
        try {
            val message = PairingProof(p.offer.sessionId, proof, pendingRevocations.tokens(p.offer.hostId))
            check(transportSink?.invoke(Message.PairingProofMessage(message).toFrame()) == true)
        } finally { proof.fill(0) }
        _state.value = SessionState.PairingFinalizing(p.hostName)
    }

    @Synchronized
    fun confirmPairing(enteredCode: String? = null): Boolean {
        val p = pendingPairing ?: return false
        return try {
            if (p.offer.expiresAt <= System.currentTimeMillis() / 1000) error("expired")
            when {
                p.offer.codeEntry == CodeEntry.DEVICE && _state.value is SessionState.PairingAwaitingConfirmation -> {
                    val code = enteredCode.orEmpty()
                    require(code.length == 6 && code.all { it in '0'..'9' })
                    startExchange(p, code.toByteArray(Charsets.US_ASCII))
                    _state.value = SessionState.PairingAwaitingCode(p.hostName)
                }
                p.offer.codeEntry == CodeEntry.HOST && _state.value is SessionState.PairingAwaitingApproval -> sendProof(p)
                else -> return false
            }
            true
        } catch (_: Exception) { abortPairing("pairing failed"); false }
          catch (_: LinkageError) { abortPairing("native enrollment library unavailable"); false }
    }

    @Synchronized
    fun handlePairingResult(result: PairingResult): SessionState {
        val p = pendingPairing ?: return abortPairing("unexpected pairing result")
        return try {
            require(p.proofSent && result.sessionId == p.offer.sessionId && result.status == 0L)
            require(p.offer.expiresAt > System.currentTimeMillis() / 1000)
            val token = result.revocationToken ?: return abortPairing("missing revocation token")
            val host = KnownHost(hostId = p.offer.hostId, keyId = p.offer.hostKeyId,
                publicKeyBytes = p.offer.hostPublicKey, pinnedCertificate = p.certificate,
                hostName = p.hostName, revocationToken = token)
            val pending = ConfirmedPairing(result.sessionId, host, p.hostName)
            // Durable phone storage precedes the acknowledgement; the host
            // commits only after that acknowledgement and sends a receipt.
            check(hosts.putDurably(host))
            clearPairing()
            _hosts.value = hosts.all()
            pendingAcknowledgement = pending
            confirmationTimeout?.cancel()
            check(transportSink?.invoke(Message.PairingConfirmedMessage(PairingConfirmed(result.sessionId)).toFrame()) == true)
            confirmationTimeout = scope.launch {
                delay(PAIRING_CONFIRMATION_TIMEOUT_MS)
                synchronized(this@AuthenticatorSession) {
                    if (pendingAcknowledgement === pending) abortPairing("host did not confirm pairing; pair again")
                }
            }
            _state.value = SessionState.PairingFinalizing(p.hostName)
            _state.value
        } catch (_: Exception) { abortPairing("pairing could not be completed") }
    }

    private fun abortPairing(reason: String): SessionState {
        clearPairing()
        pendingAcknowledgement = null
        confirmationTimeout?.cancel()
        confirmationTimeout = null
        pairingSettledListener?.invoke()
        return fail(reason)
    }

    /** Accept the receipt only on the original link and for the pending session. */
    @Synchronized
    fun handlePairingReceipt(sessionId: Id): Boolean {
        val pending = pendingAcknowledgement ?: return false
        if (pending.sessionId != sessionId) return false
        pendingAcknowledgement = null
        confirmationTimeout?.cancel()
        confirmationTimeout = null
        pendingRevocations.clear(pending.host.hostId)
        _hosts.value = hosts.all()
        _state.value = SessionState.PairingConfirmed(pending.hostName)
        pairingSettledListener?.invoke()
        return true
    }

    /** The operator rejected the pairing, or closed the confirmation. */
    @Synchronized
    fun rejectPairing(): SessionState = abortPairing("pairing was not confirmed")

    /**
     * Clears a terminal result after the operator has read it.
     *
     * Manual launches have no auto-close timer. Pairing completion and the
     * approved/denied/failed results are informational; returning to idle keeps
     * the paired hosts and the background link intact.
     */
    fun dismissResult(): SessionState {
        val current = _state.value
        if (current is SessionState.PairingConfirmed ||
            current is SessionState.Approved ||
            current is SessionState.Denied ||
            current is SessionState.Failed
        ) {
            _state.value = SessionState.Idle
        }
        return _state.value
    }

    // -----------------------------------------------------------------------
    // Authentication
    // -----------------------------------------------------------------------

    /**
     * Presents a request to the operator and signs it if they approve.
     *
     */
    fun requestApproval(request: AuthRequest) {
        // Refuse anything we cannot attribute to a paired host before showing
        // the operator anything at all.
        if (hosts.all().none { it.hostId == request.hostId }) {
            _state.value = SessionState.Denied(
                request.requestId.toHex(),
                "this host is not paired with this device",
            )
            send(
                Message.AuthRejectMessage(
                    io.github.burtvadr.rba.protocol.AuthReject(
                        request.requestId,
                        ErrorCode.NOT_PAIRED.code,
                    ),
                ).toFrame(),
            )
            return
        }
        if (request.deviceId != deviceId) {
            _state.value = SessionState.Denied(
                request.requestId.toHex(),
                "this request is addressed to a different device",
            )
            return
        }

        // Rate limiting on the device side, so a malicious host cannot spam the
        // operator with prompts. This is a sliding window: five prompts in any
        // sixty seconds, after which the operator gets a minute of quiet.
        val nowMillis = System.currentTimeMillis()
        promptTimes.removeAll { nowMillis - it >= PROMPT_WINDOW_MS }
        if (promptTimes.size >= MAX_PROMPTS_PER_WINDOW) {
            _state.value = SessionState.Denied(
                request.requestId.toHex(),
                "too many requests; try again later",
            )
            send(
                Message.AuthRejectMessage(
                    io.github.burtvadr.rba.protocol.AuthReject(
                        request.requestId,
                        ErrorCode.RATE_LIMITED.code,
                    ),
                ).toFrame(),
            )
            return
        }
        promptTimes.addLast(nowMillis)

        pendingRequest = request
        _state.value = SessionState.AwaitingApproval(
            request,
            trustedHostName(request.hostId),
            request.hostId.toHex(),
        )
    }

    /**
     * Runs the biometric check for the request the operator has just approved.
     *
     * Kept separate from [requestApproval] so the ordering is explicit at the call
     * site: show the context, then approve, then authenticate, then sign.
     *
     * @param activity a `FragmentActivity`, which `BiometricPrompt` requires.
     * @param executor the executor for the prompt callbacks.
     * @param availability what this device can actually offer.
     */
    fun beginBiometricCheck(
        activity: androidx.fragment.app.FragmentActivity,
        executor: Executor,
        availability: BiometricAvailability,
    ): androidx.biometric.BiometricPrompt? {
        val request = pendingRequest ?: return null

        // Prepare the signature *before* the prompt. Keystore authorises this exact
        // object when the biometric succeeds; it is not enough to authenticate and
        // then create a fresh Signature, which would be refused as unauthenticated.
        //
        // An existing operation can only belong to this same pending request (a
        // second request is rejected while one is being decided). It is reused when
        // the activity was recreated, for example after a rotation, because the
        // Signature is still the object Keystore will authorise.
        val operation = signingOperation ?: run {
            val prepared = key.beginSigning(request.signingInput())
            if (prepared == null) {
                reject(request, ErrorCode.BIOMETRIC_FAILED)
                _state.value = SessionState.Denied(
                    request.requestId.toHex(),
                    "the device key could not prepare a signature; re-pairing may be required",
                )
                return null
            }
            signingOperation = prepared
            prepared
        }

        // The operator's approval is bound to this exact request id.
        approvedRequestId = request.requestId.toHex()
        _state.value = SessionState.AwaitingBiometric(
            request,
            trustedHostName(request.hostId),
            request.hostId.toHex(),
        )

        return authenticateStrong(
            activity = activity,
            executor = executor,
            availability = availability,
            title = "Host authentication",
            subtitle = request.username,
            description = describe(request),
            cryptoObject = androidx.biometric.BiometricPrompt.CryptoObject(
                operation.signature,
            ),
            onResult = { outcome -> onBiometricResult(request, operation, outcome) },
        )
    }

    /**
     * Operator declined. No prompt is shown and nothing is signed.
     */
    fun reject(request: AuthRequest, reason: ErrorCode = ErrorCode.USER_CANCELLED) {
        approvedRequestId = null
        signingOperation = null
        // The request is settled. Leaving it pending would let a later link loss
        // overwrite the operator-visible denial with a misleading reason.
        if (pendingRequest?.requestId == request.requestId) pendingRequest = null
        _state.value = SessionState.Denied(request.requestId.toHex(), "declined")
        send(
            Message.AuthRejectMessage(
                io.github.burtvadr.rba.protocol.AuthReject(request.requestId, reason.code),
            ).toFrame(),
        )
    }

    private fun onBiometricResult(
        request: AuthRequest,
        operation: DeviceAuthKey.SigningOperation,
        outcome: BiometricOutcome,
    ) {
        if (signingOperation !== operation) {
            // The request was declined or the link was lost while the prompt was up.
            // A late success must not authorise anything.
            return
        }
        when (outcome) {
            is BiometricOutcome.Succeeded -> {
                signingOperation = null
                signAndSend(request, operation)
            }
            is BiometricOutcome.NotRecognised -> Unit // the prompt is still up
            is BiometricOutcome.Failed -> {
                signingOperation = null
                val reason = when (outcome.code) {
                    androidx.biometric.BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                    androidx.biometric.BiometricPrompt.ERROR_USER_CANCELED,
                    -> "declined"
                    else -> outcome.message
                }
                reject(request, ErrorCode.USER_CANCELLED)
                _state.value = SessionState.Denied(request.requestId.toHex(), reason)
            }
            is BiometricOutcome.Unavailable -> {
                // A device that cannot satisfy the strong-biometric policy must say
                // so plainly rather than quietly proceed.
                signingOperation = null
                reject(request, ErrorCode.BIOMETRIC_FAILED)
                _state.value = SessionState.Denied(
                    request.requestId.toHex(),
                    unavailableMessage(outcome.reason),
                )
            }
        }
    }

    private fun unavailableMessage(reason: BiometricAvailability): String = when (reason) {
        is BiometricAvailability.NotEnrolled ->
            "no strong biometric is enrolled; add a fingerprint or a strong face model"
        is BiometricAvailability.NoHardware ->
            "this device has no biometric sensor that can be used for authentication"
        is BiometricAvailability.TemporarilyUnavailable -> "biometrics unavailable: ${reason.reason}"
        is BiometricAvailability.InsufficientStrength ->
            "this device does not provide a strong biometric that can be used for " +
                "cryptographic authentication (available: ${reason.available.joinToString()})"
        BiometricAvailability.Available -> "biometrics unavailable"
    }

    /**
     * Signs the request and sends the response.
     *
     * The signature covers [AuthRequest.signingInput], which binds the domain
     * separator, the protocol version and exactly the ten signed fields. Nothing
     * else is signed, so no unsigned display text can gain authority.
     */
    private fun signAndSend(
        request: AuthRequest,
        operation: DeviceAuthKey.SigningOperation,
    ) {
        // The biometric that just succeeded must belong to *this* request, still be
        // the request on screen, and use the object the prompt authorised.
        if (approvedRequestId != request.requestId.toHex() ||
            pendingRequest?.requestId != request.requestId
        ) {
            reject(request, ErrorCode.INTERNAL)
            _state.value = SessionState.Denied(
                request.requestId.toHex(),
                "the confirmation did not match this request",
            )
            return
        }
        val signature = operation.sign()
        if (signature == null) {
            // Keystore refused: no recent strong authentication, or the key was
            // invalidated by a re-enrollment. Either way this is a denial.
            approvedRequestId = null
            pendingRequest = null
            reject(request, ErrorCode.BIOMETRIC_FAILED)
            _state.value = SessionState.Denied(
                request.requestId.toHex(),
                "the device key could not sign; re-pairing may be required",
            )
            return
        }
        val publicKeyBytes = key.publicKeyBytes()
        if (publicKeyBytes == null) {
            approvedRequestId = null
            pendingRequest = null
            reject(request, ErrorCode.INTERNAL)
            _state.value = SessionState.Denied(
                request.requestId.toHex(),
                "the device public key is unavailable",
            )
            return
        }
        val response = AuthResponse(
            requestId = request.requestId,
            deviceId = deviceId,
            sessionId = request.sessionId,
            keyId = Hex.encode(sha256(publicKeyBytes)),
            signature = signature,
        )
        send(Message.AuthResponseMessage(response).toFrame())
        approvedRequestId = null
        pendingRequest = null
        _state.value = SessionState.Approved(
            request,
            trustedHostName(request.hostId),
            request.hostId.toHex(),
        )
    }

    /**
     * The locally stored label for a paired host. The `display_host_name` field in
     * the request is unsigned and must never be the primary identity shown to the
     * operator; it is presented separately as unverified metadata.
     */
    private fun trustedHostName(hostId: Id): String =
        hosts.get(hostId)?.hostName?.takeIf { it.isNotBlank() }
            ?: "Unknown host"

    /** Human-readable summary of exactly what is being authorised. */
    private fun describe(request: AuthRequest): String = buildString {
        append("Host: ${trustedHostName(request.hostId)} (${request.hostId.toHex().take(16)})\n")
        append("User: ${request.username}\n")
        append("Service: ${request.service}\n")
        append("Operation: ${request.operation}\n")
        append("Action: ${request.purpose}")
    }

    private fun fail(message: String): SessionState {
        _state.value = SessionState.Failed(message)
        return _state.value
    }

    // -----------------------------------------------------------------------
    // Transport plumbing
    // -----------------------------------------------------------------------

    private fun send(frame: Frame) {
        transportSink?.invoke(frame)
    }

    /** Prompt timestamps inside the current rate-limit window. */
    private val promptTimes = ArrayDeque<Long>()

    private companion object {
        const val MAX_PROMPTS_PER_WINDOW = 5
        const val PROMPT_WINDOW_MS = 60_000L

        /**
         * How long a verified pairing waits for the operator's Allow tap.
         *
         * The host's pairing session has its own TTL. Keeping the device's parked
         * record shorter than that would be surprising; keeping it forever would
         * block every later pairing.
         */
        const val PAIRING_CONFIRMATION_TIMEOUT_MS = 120_000L
    }
}