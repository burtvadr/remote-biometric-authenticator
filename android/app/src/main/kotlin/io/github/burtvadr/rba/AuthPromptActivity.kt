package io.github.burtvadr.rba

import android.graphics.Color
import android.os.Bundle
import android.widget.FrameLayout
import androidx.activity.addCallback
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.lifecycle.whenResumed
import io.github.burtvadr.rba.biometric.BiometricGatekeeper
import io.github.burtvadr.rba.runtime.AuthenticatorRuntime
import io.github.burtvadr.rba.service.AuthNotifications
import io.github.burtvadr.rba.session.AuthenticatorSession
import io.github.burtvadr.rba.session.SessionState
import kotlinx.coroutines.launch

/**
 * Invisible host for an automatically opened authentication prompt.
 *
 * The activity window is transparent, so the operator sees the system
 * BiometricPrompt over whatever app was in front. No authenticator UI is drawn,
 * and the activity finishes as soon as the prompt produces a terminal state.
 *
 * Pairing deliberately does not use this: it needs the code/Allow screen.
 */
class AuthPromptActivity : FragmentActivity() {

    private lateinit var session: AuthenticatorSession
    private lateinit var gatekeeper: BiometricGatekeeper
    private var activePrompt: BiometricPrompt? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setBackgroundDrawableResource(android.R.color.transparent)
        window.setDimAmount(0f)
        window.clearFlags(android.view.WindowManager.LayoutParams.FLAG_DIM_BEHIND)
        setContentView(FrameLayout(this).apply { setBackgroundColor(Color.TRANSPARENT) })

        AuthNotifications.clearRequest(this)
        session = AuthenticatorRuntime.start(this)
        gatekeeper = BiometricGatekeeper(this)

        if (session.state.value !is SessionState.AwaitingApproval) {
            finish()
            return
        }

        onBackPressedDispatcher.addCallback(this) {
            session.declinePending()
            session.dismissResult()
            finish()
        }

        lifecycleScope.launch {
            lifecycle.whenResumed {
                if (isFinishing || isDestroyed) return@whenResumed
                if (session.state.value !is SessionState.AwaitingApproval) {
                    finish()
                    return@whenResumed
                }
                activePrompt = session.beginBiometricCheck(
                    activity = this@AuthPromptActivity,
                    executor = ContextCompat.getMainExecutor(this@AuthPromptActivity),
                    availability = gatekeeper.availability(),
                )
            }
        }

        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                session.state.collect { state ->
                    when (state) {
                        is SessionState.Approved,
                        is SessionState.Denied,
                        is SessionState.Failed,
                        -> finishSilently()
                        else -> Unit
                    }
                }
            }
        }
    }

    override fun onStart() {
        super.onStart()
        AuthenticatorRuntime.setActivityVisible(true)
    }

    override fun onStop() {
        AuthenticatorRuntime.setActivityVisible(false)
        super.onStop()
    }

    override fun onDestroy() {
        val terminal = session.state.value
        if (isFinishing &&
            (terminal is SessionState.AwaitingApproval ||
                terminal is SessionState.AwaitingBiometric)
        ) {
            session.declinePending()
        }
        activePrompt = null
        super.onDestroy()
    }

    private fun finishSilently() {
        activePrompt = null
        session.dismissResult()
        if (!isFinishing) finishAndRemoveTask()
    }
}
