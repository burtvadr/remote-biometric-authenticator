package io.github.burtvadr.rba

import android.Manifest
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import androidx.activity.OnBackPressedCallback
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.biometric.BiometricPrompt
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.lifecycle.whenResumed
import io.github.burtvadr.rba.biometric.BiometricGatekeeper
import io.github.burtvadr.rba.appearance.AppIconController
import io.github.burtvadr.rba.appearance.ThemeMode
import io.github.burtvadr.rba.protocol.AuthRequest
import io.github.burtvadr.rba.runtime.AuthenticatorRuntime
import io.github.burtvadr.rba.runtime.OperatorLaunch
import io.github.burtvadr.rba.service.AppSettings
import io.github.burtvadr.rba.service.AuthNotifications
import io.github.burtvadr.rba.service.AuthService
import io.github.burtvadr.rba.session.AuthenticatorSession
import io.github.burtvadr.rba.session.SessionState
import io.github.burtvadr.rba.ui.AuthenticatorScreen
import io.github.burtvadr.rba.ui.BackgroundStatus
import io.github.burtvadr.rba.ui.theme.AppTheme
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * The single activity.
 *
 * It owns no protocol state: that lives in the process-wide
 * [AuthenticatorRuntime] so the foreground service and the screen see exactly the
 * same session. This class only bridges Android's activity lifecycle to Compose and
 * to `BiometricPrompt`.
 */
class MainActivity : androidx.fragment.app.FragmentActivity() {

    private lateinit var session: AuthenticatorSession
    private lateinit var gatekeeper: BiometricGatekeeper

    private val background = mutableStateOf(
        BackgroundStatus(
            notificationsAllowed = false,
            canDrawOverlays = false,
            ignoringBatteryOptimizations = false,
            fullScreenIntentAllowed = false,
        ),
    )

    private var activePrompt: BiometricPrompt? = null
    private var promptedRequestId: String? = null
    private var expiryJob: Job? = null
    private var autoCloseJob: Job? = null
    private var autoOpened = false

    private val notificationPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { refreshBackgroundStatus() }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val activeSession = AuthenticatorRuntime.start(this)
        session = activeSession
        gatekeeper = BiometricGatekeeper(this)
        autoOpened = intent?.getBooleanExtra(OperatorLaunch.EXTRA_AUTO_OPEN, false) == true

        // Start the background link first, then clear the request notification that
        // may have opened this screen.
        AuthService.start(this)
        AuthNotifications.clearRequest(this)
        if (!AppSettings.notificationAsked(this)) {
            AppSettings.setNotificationAsked(this, true)
            requestNotificationPermission()
        }

        installBackHandler()

        var themeMode by mutableStateOf(AppSettings.themeMode(this))
        var iconStyle by mutableStateOf(AppSettings.iconStyle(this))
        var dynamicColor by mutableStateOf(AppSettings.dynamicColor(this))
        AppIconController.apply(this, iconStyle, isDark(themeMode))

        setContent {
            AppTheme(themeMode = themeMode, dynamicColor = dynamicColor) {
                val state by activeSession.state.collectAsStateWithLifecycle()
                val knownHosts by activeSession.knownHostsFlow.collectAsStateWithLifecycle()
                val connectedHostId by activeSession.connectedHostId.collectAsStateWithLifecycle()
                val discoveredKeyIds by activeSession.discoveredKeyIds.collectAsStateWithLifecycle()
                val backgroundStatus by background
                AuthenticatorScreen(
                    state = state,
                    deviceId = activeSession.deviceId.toHex(),
                    deviceName = AuthenticatorRuntime.deviceName,
                    capabilities = AuthenticatorRuntime.capabilities,
                    hosts = knownHosts,
                    connectedHostId = connectedHostId,
                    discoveredKeyIds = discoveredKeyIds,
                    background = backgroundStatus,
                    themeMode = themeMode,
                    iconStyle = iconStyle,
                    dynamicColor = dynamicColor,
                    onThemeModeChange = {
                        themeMode = it
                        AppSettings.setThemeMode(this@MainActivity, it)
                        AppIconController.apply(this@MainActivity, iconStyle, isDark(it))
                    },
                    onIconStyleChange = {
                        iconStyle = it
                        AppSettings.setIconStyle(this@MainActivity, it)
                        AppIconController.apply(this@MainActivity, it, isDark(themeMode))
                    },
                    onDynamicColorChange = {
                        dynamicColor = it
                        AppSettings.setDynamicColor(this@MainActivity, it)
                    },
                    onConfirmPairing = { code -> activeSession.confirmPairing(code) },
                    onRejectPairing = { activeSession.rejectPairing() },
                    onForgetHost = { id -> activeSession.forgetHost(id) },
                    onFixNotifications = ::openNotificationSettings,
                    onFixOverlay = ::openOverlaySettings,
                    onFixBattery = ::requestBatteryExemption,
                    onFixFullScreen = ::openFullScreenIntentSettings,
                    versionName = BuildConfig.VERSION_NAME,
                    isDebug = BuildConfig.DEBUG,
                )
            }
        }

        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                activeSession.state.collect { state -> handleState(state) }
            }
        }
    }

    private fun handleState(state: SessionState) {
        when (state) {
            is SessionState.AwaitingApproval -> {
                cancelAutoClose()
                maybePrompt(state.request)
            }
            is SessionState.AwaitingBiometric -> {
                cancelAutoClose()
                maybePrompt(state.request)
            }
            is SessionState.PairingAwaitingConfirmation -> {
                cancelAutoClose()
                dropPromptReference()
            }
            is SessionState.PairingAwaitingHostCode -> {
                cancelAutoClose()
                dropPromptReference()
            }
            is SessionState.PairingAwaitingApproval -> {
                cancelAutoClose()
                dropPromptReference()
            }
            is SessionState.PairingFinalizing,
            is SessionState.PairingAwaitingCode -> {
                cancelAutoClose()
                dropPromptReference()
            }
            is SessionState.Approved -> {
                dropPromptReference()
                scheduleTerminalDismiss(700L)
            }
            is SessionState.Denied -> {
                dismissPrompt()
                scheduleTerminalDismiss(700L)
            }
            is SessionState.PairingConfirmed -> {
                dropPromptReference()
                schedulePairingOverview(700L)
            }
            is SessionState.Failed -> {
                dismissPrompt()
                scheduleTerminalDismiss(700L)
            }
            SessionState.Idle -> Unit
        }
    }

    /**
     * Opens the biometric prompt for the request, once.
     *
     * There is no approval button: the prompt is the decision, and every negative
     * path inside it (back, cancel, home) becomes an `AuthReject`.
     */
    private fun maybePrompt(request: AuthRequest) {
        val requestId = request.requestId.toHex()
        if (promptedRequestId == requestId) return
        lifecycleScope.launch {
            // onResume can run before the lifecycle has actually reached RESUMED, and
            // a request can arrive while the activity is still starting. Waiting for
            // the resumed state avoids silently dropping the prompt.
            lifecycle.whenResumed {
                if (promptedRequestId == requestId) return@whenResumed
                if (session.pendingRequest()?.requestId != request.requestId) return@whenResumed
                promptedRequestId = requestId
                activePrompt = session.beginBiometricCheck(
                    activity = this@MainActivity,
                    executor = ContextCompat.getMainExecutor(this@MainActivity),
                    availability = gatekeeper.availability(),
                )
                scheduleExpiry(request)
            }
        }
    }

    /** Re-arms the prompt after the activity was recreated, e.g. by a rotation. */
    private fun maybePromptForCurrentState() {
        when (val state = session.state.value) {
            is SessionState.AwaitingApproval -> maybePrompt(state.request)
            is SessionState.AwaitingBiometric -> maybePrompt(state.request)
            else -> Unit
        }
    }

    private fun scheduleExpiry(request: AuthRequest) {
        expiryJob?.cancel()
        val remaining = request.expiresAt * 1000L - System.currentTimeMillis()
        if (remaining <= 0L) {
            dismissPrompt()
            session.declinePending()
            return
        }
        expiryJob = lifecycleScope.launch {
            delay(remaining)
            if (session.pendingRequest()?.requestId == request.requestId) {
                dismissPrompt()
                session.declinePending()
            }
        }
    }

    private fun dropPromptReference() {
        activePrompt = null
        promptedRequestId = null
        expiryJob?.cancel()
        expiryJob = null
    }

    private fun dismissPrompt() {
        val prompt = activePrompt
        dropPromptReference()
        runCatching { prompt?.cancelAuthentication() }
    }

    private fun scheduleTerminalDismiss(delayMillis: Long) {
        if (autoCloseJob?.isActive == true) return
        autoCloseJob = lifecycleScope.launch {
            delay(delayMillis)
            if (isFinishing || isDestroyed) return@launch
            if (autoOpened) {
                finishAndRemoveTask()
            } else {
                session.dismissResult()
            }
        }
    }

    private fun schedulePairingOverview(delayMillis: Long) {
        if (autoCloseJob?.isActive == true) return
        autoCloseJob = lifecycleScope.launch {
            delay(delayMillis)
            if (!isFinishing && !isDestroyed) session.dismissResult()
        }
    }

    private fun cancelAutoClose() {
        autoCloseJob?.cancel()
        autoCloseJob = null
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        if (intent.getBooleanExtra(OperatorLaunch.EXTRA_AUTO_OPEN, false)) {
            autoOpened = true
            cancelAutoClose()
        }
        AuthNotifications.clearRequest(this)
    }

    override fun onConfigurationChanged(newConfig: Configuration) {
        super.onConfigurationChanged(newConfig)
        if (::session.isInitialized) {
            AppIconController.apply(
                this,
                AppSettings.iconStyle(this),
                isDark(AppSettings.themeMode(this)),
            )
        }
    }

    private fun isDark(mode: ThemeMode): Boolean {
        val systemDark =
            (resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) ==
                Configuration.UI_MODE_NIGHT_YES
        return when (mode) {
            ThemeMode.SYSTEM -> systemDark
            ThemeMode.LIGHT -> false
            ThemeMode.DARK -> true
        }
    }

    override fun onStart() {
        super.onStart()
        AuthenticatorRuntime.setActivityVisible(true)
        AuthNotifications.clearRequest(this)
    }

    override fun onResume() {
        super.onResume()
        refreshBackgroundStatus()
        AuthNotifications.clearRequest(this)
        maybePromptForCurrentState()
    }

    override fun onStop() {
        super.onStop()
        AuthenticatorRuntime.setActivityVisible(false)

        // A configuration change destroys the screen but not the decision. The
        // prepared Signature survives, and the recreated activity re-opens the
        // prompt. Anything else means the operator left; an unanswered request is a
        // denial.
        if (!isChangingConfigurations) {
            val state = session.state.value
            if (state is SessionState.AwaitingApproval ||
                state is SessionState.AwaitingBiometric
            ) {
                dismissPrompt()
                session.declinePending()
            } else {
                dismissPrompt()
            }
        }
    }

    override fun onDestroy() {
        expiryJob?.cancel()
        autoCloseJob?.cancel()
        activePrompt = null
        super.onDestroy()
    }

    private fun installBackHandler() {
        onBackPressedDispatcher.addCallback(
            this,
            object : OnBackPressedCallback(true) {
                override fun handleOnBackPressed() {
                    when (session.state.value) {
                        is SessionState.PairingAwaitingConfirmation,
                        is SessionState.PairingAwaitingApproval,
                        is SessionState.PairingAwaitingHostCode,
                        is SessionState.PairingAwaitingCode,
                        -> session.rejectPairing()

                        is SessionState.AwaitingApproval,
                        is SessionState.AwaitingBiometric,
                        -> {
                            dismissPrompt()
                            session.declinePending()
                        }

                        else -> {
                            isEnabled = false
                            onBackPressedDispatcher.onBackPressed()
                        }
                    }
                }
            },
        )
    }

    // -----------------------------------------------------------------------
    // Background permissions
    // -----------------------------------------------------------------------

    private fun refreshBackgroundStatus() {
        val notifications = Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
            ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.POST_NOTIFICATIONS,
            ) == PackageManager.PERMISSION_GRANTED
        val overlay = Settings.canDrawOverlays(this)
        val battery = (getSystemService(Context.POWER_SERVICE) as PowerManager)
            .isIgnoringBatteryOptimizations(packageName)
        val fullScreen = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            getSystemService(NotificationManager::class.java)?.canUseFullScreenIntent() == true
        } else {
            true
        }
        background.value = BackgroundStatus(
            notificationsAllowed = notifications,
            canDrawOverlays = overlay,
            ignoringBatteryOptimizations = battery,
            fullScreenIntentAllowed = fullScreen,
        )
    }

    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        if (ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.POST_NOTIFICATIONS,
            ) == PackageManager.PERMISSION_GRANTED
        ) {
            return
        }
        notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
    }

    private fun openNotificationSettings() {
        startActivity(
            Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
                .putExtra(Settings.EXTRA_APP_PACKAGE, packageName),
        )
    }

    private fun openOverlaySettings() {
        openSettings(
            Intent(
                Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                Uri.parse("package:$packageName"),
            ),
        )
    }

    private fun requestBatteryExemption() {
        openSettings(
            Intent(
                Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                Uri.parse("package:$packageName"),
            ),
        )
    }

    private fun openFullScreenIntentSettings() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE) return
        openSettings(
            Intent(
                Settings.ACTION_MANAGE_APP_USE_FULL_SCREEN_INTENT,
                Uri.parse("package:$packageName"),
            ),
        )
    }

    private fun openSettings(intent: Intent) {
        runCatching { startActivity(intent) }
            .onFailure {
                runCatching { startActivity(Intent(Settings.ACTION_SETTINGS)) }
            }
    }
}

/**
 * The app's stable identity.
 *
 * A random 128-bit identifier generated once and kept in private storage. It is
 * deliberately *not* derived from anything the platform exposes about the device:
 * identity must come from the key, and the identifier only names the key in logs
 * and on the host side.
 */
object DeviceIdentity {
    private const val PREFS = "rba-identity"
    private const val KEY_ID = "device_id"
    private const val KEY_NAME = "device_name"

    fun load(context: Context): io.github.burtvadr.rba.protocol.Id {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        prefs.getString(KEY_ID, null)?.let { existing ->
            return runCatching { io.github.burtvadr.rba.protocol.Id.fromHex(existing) }
                .getOrElse { generate(prefs) }
        }
        return generate(prefs)
    }

    private fun generate(
        prefs: android.content.SharedPreferences,
    ): io.github.burtvadr.rba.protocol.Id {
        val id = io.github.burtvadr.rba.protocol.Id.random()
        prefs.edit().putString(KEY_ID, id.toHex()).apply()
        return id
    }

    fun name(context: Context): String =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(KEY_NAME, null)
            ?: run {
                val model = Build.MODEL ?: "Android"
                val label = "$model".replace(Regex("[^A-Za-z0-9 _-]"), "").trim().take(32)
                    .ifEmpty { "Android device" }
                context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                    .edit().putString(KEY_NAME, label).apply()
                label
            }
}
