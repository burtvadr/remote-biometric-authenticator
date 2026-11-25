package io.github.burtvadr.rba.keystore

import android.os.Looper
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import io.github.burtvadr.rba.biometric.BiometricAvailability
import io.github.burtvadr.rba.biometric.BiometricGatekeeper
import java.security.Signature

/** One immutable transcript, one prepared Signature and one terminal outcome.
 * A UI success alone never produces evidence. No device-credential fallback.
 * Call on the main thread; the session owner must cancel on disconnect,
 * expiration, policy change or activity teardown and revalidate on completion. */
internal class V2BiometricOperation internal constructor(private val signature: Signature, transcript: ByteArray) {
    private val message = transcript.copyOf()
    private var started = false
    private var terminal = false
    private var prompt: BiometricPrompt? = null
    private var completion: ((Result<ByteArray>) -> Unit)? = null

    private fun mainThread() = check(Looper.myLooper() == Looper.getMainLooper())
    private fun finish(outcome: Result<ByteArray>, cancelFramework: Boolean = false) {
        if (terminal) return
        terminal = true
        message.fill(0)
        val p = prompt; prompt = null
        val callback = completion; completion = null
        if (cancelFramework) runCatching { p?.cancelAuthentication() }
        callback?.invoke(outcome)
    }
    fun authenticate(activity: FragmentActivity, title: String, subtitle: String, description: String,
                     onResult: (Result<ByteArray>) -> Unit) {
        mainThread(); check(!started && !terminal); started = true; completion = onResult
        try {
            val gatekeeper = BiometricGatekeeper(activity)
            check(gatekeeper.availability() is BiometricAvailability.Available)
            val p = BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    mainThread()
                    if (terminal) return
                    val proof = runCatching {
                        check(result.cryptoObject?.signature === signature) { "Unexpected biometric operation" }
                        // Keystore authorizes this exact operation, not a later
                        // Signature initialized after a successful prompt.
                        signature.update(message)
                        V2KeyEncoding.rawSignature(signature.sign())
                    }
                    finish(proof)
                }
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    mainThread(); finish(Result.failure(SecurityException("Strong biometric denied ($errorCode)")))
                }
                // A nonterminal unrecognized biometric is handled by the OS prompt.
            })
            prompt = p
            p.authenticate(gatekeeper.promptInfo(title, subtitle, description), BiometricPrompt.CryptoObject(signature))
        } catch (e: Exception) {
            finish(Result.failure(e), cancelFramework = true)
        }
    }
    fun cancel() {
        mainThread()
        if (terminal) return
        // Make the state terminal before asking the framework to cancel.
        // A late callback cannot sign after cancellation.
        finish(Result.failure(SecurityException("Biometric operation cancelled")), cancelFramework = true)
    }
}
