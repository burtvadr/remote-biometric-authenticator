package io.github.burtvadr.rba.ui

/** Display-only model. No protocol messages, keys, tokens or authorization handles. */
data class HostPresentation(
    val hostId: String,
    val keyId: String,
    val hostName: String,
    val certificatePinned: Boolean,
)

enum class KeyStoragePresentation { STRONGBOX, HARDWARE, SOFTWARE }

data class SecurityPresentation(
    val location: KeyStoragePresentation?,
    val strongBiometricEnrolled: Boolean,
)

data class RequestPresentation(
    val username: String,
    val purpose: String,
    val service: String,
    val operation: String,
    val displayDetail: String? = null,
)

/** Rendering cannot decide trust or construct cryptographic responses. */
sealed interface ScreenState {
    data object Idle : ScreenState
    data class PairingAwaitingCode(val hostName: String) : ScreenState
    data class PairingAwaitingHostCode(val hostName: String, val code: String) : ScreenState
    data class PairingAwaitingConfirmation(val hostName: String) : ScreenState
    data class PairingAwaitingApproval(val hostName: String, val code: String) : ScreenState
    data class PairingFinalizing(val hostName: String) : ScreenState
    data class PairingConfirmed(val hostName: String) : ScreenState
    data class AwaitingApproval(val request: RequestPresentation, val hostName: String, val hostKeyId: String) : ScreenState
    data class AwaitingBiometric(val request: RequestPresentation, val hostName: String, val hostKeyId: String) : ScreenState
    data class Approved(val request: RequestPresentation, val hostName: String, val hostKeyId: String) : ScreenState
    data class Denied(val requestId: String, val reason: String) : ScreenState
    data class Failed(val message: String) : ScreenState
}
