package io.github.burtvadr.rba.runtime

import android.content.Context
import android.content.Intent
import android.provider.Settings
import android.util.Log
import io.github.burtvadr.rba.AuthPromptActivity
import io.github.burtvadr.rba.DeviceIdentity
import io.github.burtvadr.rba.MainActivity
import io.github.burtvadr.rba.keystore.DeviceAuthKey
import io.github.burtvadr.rba.protocol.Id
import io.github.burtvadr.rba.service.AuthNotifications
import io.github.burtvadr.rba.session.AuthenticatorSession
import io.github.burtvadr.rba.session.HostLink
import io.github.burtvadr.rba.session.HostStore
import io.github.burtvadr.rba.session.SessionState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/** What the app needs the operator to look at. */
enum class OperatorRequestKind {
    AUTHENTICATION,
    PAIRING,
}

/** Builds the intent that brings the authentication screen forward. */
object OperatorLaunch {
    const val EXTRA_AUTO_OPEN = "io.github.burtvadr.rba.extra.AUTO_OPEN"
    const val EXTRA_KIND = "io.github.burtvadr.rba.extra.KIND"

    fun intent(context: Context, kind: OperatorRequestKind): Intent {
        val target = when (kind) {
            OperatorRequestKind.AUTHENTICATION -> AuthPromptActivity::class.java
            OperatorRequestKind.PAIRING -> MainActivity::class.java
        }
        return Intent(context, target).apply {
            action = Intent.ACTION_VIEW
            putExtra(EXTRA_AUTO_OPEN, true)
            putExtra(EXTRA_KIND, kind.name)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            if (kind == OperatorRequestKind.AUTHENTICATION) {
                addFlags(Intent.FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS or Intent.FLAG_ACTIVITY_NO_ANIMATION)
            }
        }
    }
}

/**
 * Process-wide owner of the key, session and host link.
 *
 * Both the foreground service and the activity use this one instance. That matters
 * for more than tidiness: two sessions would mean two connections, two sets of
 * pending confirmations, and a request offered on the link the other instance is
 * not watching.
 */
object AuthenticatorRuntime {

    private const val TAG = "AuthenticatorRuntime"

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val lock = Any()

    private var appContext: Context? = null
    private var session: AuthenticatorSession? = null
    private var hostLink: HostLink? = null
    private var observer: Job? = null
    private var started = false

    var deviceId: Id? = null
        private set
    var deviceName: String = "Android device"
        private set

    /**
     * What this device's key can do, read once when the session is built.
     *
     * Re-reading it on every recomposition would create a fresh `KeyStore` and
     * re-inspect the key while the operator is looking at a prompt.
     */
    @Volatile
    var capabilities: DeviceAuthKey.Capabilities? = null
        private set

    /**
     * Whether an activity is between onStart and onStop.
     *
     * Read by the notification collector so a visible screen is never covered by a
     * full-screen notification for a request it is already showing.
     */
    @Volatile
    var activityVisible: Boolean = false
        private set

    /** The one session, or null before the first [start]. */
    fun session(): AuthenticatorSession? = synchronized(lock) { session }

    /** Starts the link and the state observer. Safe to call repeatedly. */
    fun start(context: Context): AuthenticatorSession {
        val app = context.applicationContext
        val current = synchronized(lock) {
            appContext = app
            if (!started) {
                if (session == null) buildSession(app)
                if (hostLink == null) {
                    hostLink = HostLink(app, session!!, scope)
                }
                observer = observe(app, session!!)
                started = true
            }
            hostLink?.start()
            session!!
        }
        return current
    }

    private fun buildSession(app: Context) {
        val key = DeviceAuthKey()
        val id = DeviceIdentity.load(app)
        val name = DeviceIdentity.name(app)
        val built = AuthenticatorSession(
            context = app,
            key = key,
            deviceId = id,
            deviceName = name,
            hosts = HostStore(app),
            scope = scope,
        )
        val caps = key.capabilities()
        built.setAvailability(caps?.strongBiometricEnrolled == true)
        deviceId = id
        deviceName = name
        capabilities = caps
        session = built
    }

    private fun observe(app: Context, activeSession: AuthenticatorSession): Job =
        scope.launch {
            activeSession.state.collect { state ->
                when (state) {
                    is SessionState.AwaitingApproval -> {
                        if (!activityVisible) {
                            requestOperator(app, OperatorRequestKind.AUTHENTICATION)
                        }
                    }

                    is SessionState.PairingAwaitingConfirmation,
                    is SessionState.PairingAwaitingApproval,
                    is SessionState.PairingAwaitingHostCode,
                    -> {
                        if (!activityVisible) {
                            requestOperator(app, OperatorRequestKind.PAIRING)
                        }
                    }

                    else -> AuthNotifications.clearRequest(app)
                }
            }
        }

    /**
     * Posts a full-screen-intent notification and, when the app has the overlay
     * permission, starts the activity directly.
     *
     * Android restricts background activity starts. "Display over other apps" is one
     * of the exemptions; a full-screen intent is the other path. Using both means
     * one of them gets the operator to the prompt, and a plain heads-up notification
     * is still the fallback when neither is granted.
     */
    private fun requestOperator(app: Context, kind: OperatorRequestKind) {
        AuthNotifications.showRequest(app, kind)
        if (Settings.canDrawOverlays(app)) {
            runCatching {
                app.startActivity(OperatorLaunch.intent(app, kind))
            }.onFailure { Log.w(TAG, "background start refused: ${it.message}") }
        }
    }

    /** Stops the link but keeps the process-wide objects for a later restart. */
    fun stop(reason: String = "background operation was stopped") {
        synchronized(lock) {
            if (!started) return
            started = false
            observer?.cancel()
            observer = null
            hostLink?.stop(reason)
            hostLink = null
        }
        appContext?.let { AuthNotifications.clearRequest(it) }
    }

    /** Called by the activity as it enters and leaves the foreground. */
    fun setActivityVisible(visible: Boolean) {
        activityVisible = visible
        if (visible) {
            appContext?.let { AuthNotifications.clearRequest(it) }
        }
    }

    /**
     * Releases everything. Only used when the application is shutting down; the
     * normal service stop path keeps the objects so a restart is cheap.
     */
    fun shutdown() {
        stop("the app is shutting down")
        scope.cancel()
    }
}
