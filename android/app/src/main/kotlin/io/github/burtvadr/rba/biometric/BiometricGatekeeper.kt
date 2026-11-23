package io.github.burtvadr.rba.biometric

import android.content.Context
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.util.concurrent.Executor

/**
 * Why a biometric check could not be offered.
 *
 * Modelled explicitly because the specification requires a *clear reason* rather
 * than a silent downgrade: a device with only a weak facial modality must not
 * quietly proceed.
 */
sealed interface BiometricAvailability {
    data object Available : BiometricAvailability

    /** No `BIOMETRIC_STRONG` sensor is enrolled. */
    data class NotEnrolled(val canEnroll: Boolean) : BiometricAvailability

    /** Hardware present but temporarily unavailable, e.g. too many failed attempts. */
    data class TemporarilyUnavailable(val reason: String) : BiometricAvailability

    /** No sensor at all. */
    data object NoHardware : BiometricAvailability

    /** Reported when the device exposes only a modality that cannot satisfy the
     *  cryptographic-authentication policy. */
    data class InsufficientStrength(val available: List<String>) : BiometricAvailability
}

/**
 * Guards every signing operation behind a strong biometric check.
 *
 * The security-relevant ordering is fixed by construction: this object verifies a
 * biometric *before* [DeviceAuthKey.sign] is reachable, and Keystore independently
 * refuses to sign without recent authentication. Two independent mechanisms, so a
 * bug in the UI cannot by itself produce an approval.
 */
class BiometricGatekeeper(private val context: Context) {

    private val biometricManager: BiometricManager = BiometricManager.from(context)

    fun availability(): BiometricAvailability = when (
        biometricManager.canAuthenticate(BIOMETRIC_STRONG)
    ) {
        BiometricManager.BIOMETRIC_SUCCESS -> BiometricAvailability.Available
        BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED ->
            BiometricAvailability.NotEnrolled(
                canEnroll = biometricManager.canAuthenticate(
                    BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL,
                ) == BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED,
            )
        BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> BiometricAvailability.NoHardware
        BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE ->
            BiometricAvailability.TemporarilyUnavailable("hardware unavailable")
        BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED ->
            BiometricAvailability.TemporarilyUnavailable("security update required")
        BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED ->
            BiometricAvailability.TemporarilyUnavailable("unsupported on this device")
        else -> BiometricAvailability.TemporarilyUnavailable("unavailable")
    }

    /**
     * Builds the prompt configuration.
     *
     * Note what is *not* configured: no `DEVICE_CREDENTIAL` allowance. A device
     * credential is a weaker authenticator, and permitting it here would change
     * the security class of the proof the host accepts without saying so.
     * Adding it is a deliberate future policy decision, not a default.
     */
    fun promptInfo(
        title: String,
        subtitle: String,
        description: String,
    ): BiometricPrompt.PromptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle(title)
        .setSubtitle(subtitle)
        .setDescription(description)
        .setAllowedAuthenticators(BIOMETRIC_STRONG)
        .setConfirmationRequired(true)
        .setNegativeButtonText("Cancel")
        .build()
}

/**
 * Runs one strong-biometric check and invokes [onResult] with the outcome.
 *
 * This is a thin wrapper so the Compose layer does not have to deal with
 * `BiometricPrompt`'s callback plumbing, and so the failure paths are handled in
 * exactly one place.
 */
fun authenticateStrong(
    activity: FragmentActivity,
    executor: Executor,
    availability: BiometricAvailability,
    title: String,
    subtitle: String,
    description: String,
    /**
     * The prepared signature Keystore must authorise for this prompt.
     *
     * Required: the device key demands authentication for every signature, and
     * Keystore authorises exactly the `Signature` object bound to the prompt, not
     * the app process. A prompt without this object could never produce a usable
     * signature.
     */
    cryptoObject: BiometricPrompt.CryptoObject,
    onResult: (BiometricOutcome) -> Unit,
): BiometricPrompt? {
    if (availability !is BiometricAvailability.Available) {
        onResult(BiometricOutcome.Unavailable(availability))
        return null
    }
    val prompt = BiometricPrompt(
        activity,
        executor,
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                onResult(BiometricOutcome.Succeeded)
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                // Includes user cancellation, lockout and every other error. All of
                // them are denials: the caller signs only on `Succeeded`.
                onResult(BiometricOutcome.Failed(errorCode, errString.toString()))
            }

            override fun onAuthenticationFailed() {
                // A single unrecognised finger. Not terminal, so the prompt stays up.
                onResult(BiometricOutcome.NotRecognised)
            }
        },
    )
    prompt.authenticate(
        BiometricGatekeeper(activity).promptInfo(title, subtitle, description),
        cryptoObject,
    )
    return prompt
}

/** The outcome of one biometric interaction. Only [Succeeded] permits signing. */
sealed interface BiometricOutcome {
    data object Succeeded : BiometricOutcome
    data object NotRecognised : BiometricOutcome
    data class Failed(val code: Int, val message: String) : BiometricOutcome
    data class Unavailable(val reason: BiometricAvailability) : BiometricOutcome
}

/** Remembers a [BiometricGatekeeper] for the current composition. */
@Composable
fun rememberBiometricGatekeeper(): BiometricGatekeeper {
    val context = LocalContext.current
    return remember(context) { BiometricGatekeeper(context) }
}