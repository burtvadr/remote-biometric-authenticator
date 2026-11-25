package io.github.burtvadr.rba.ui

import io.github.burtvadr.rba.keystore.DeviceAuthKey
import io.github.burtvadr.rba.protocol.AuthRequest
import io.github.burtvadr.rba.session.KnownHost
import io.github.burtvadr.rba.session.SessionState

/** Source compatibility for the inactive V1 activity only. Never used by V2. */
internal fun KnownHost.presentation() = HostPresentation(hostId.toHex(), keyId, hostName, pinnedCertificate != null)
internal fun DeviceAuthKey.Capabilities.presentation() = SecurityPresentation(
    when (location) {
        DeviceAuthKey.KeyLocation.STRONGBOX -> KeyStoragePresentation.STRONGBOX
        DeviceAuthKey.KeyLocation.HARDWARE -> KeyStoragePresentation.HARDWARE
        DeviceAuthKey.KeyLocation.SOFTWARE -> KeyStoragePresentation.SOFTWARE
    }, strongBiometricEnrolled,
)
private fun AuthRequest.presentation() = RequestPresentation(username, purpose, service, operation, displayDetail)
internal fun SessionState.presentation(): ScreenState = when (this) {
    SessionState.Idle -> ScreenState.Idle
    is SessionState.PairingAwaitingCode -> ScreenState.PairingAwaitingCode(hostName)
    is SessionState.PairingAwaitingHostCode -> ScreenState.PairingAwaitingHostCode(hostName, code)
    is SessionState.PairingAwaitingConfirmation -> ScreenState.PairingAwaitingConfirmation(hostName)
    is SessionState.PairingAwaitingApproval -> ScreenState.PairingAwaitingApproval(hostName, code)
    is SessionState.PairingFinalizing -> ScreenState.PairingFinalizing(hostName)
    is SessionState.PairingConfirmed -> ScreenState.PairingConfirmed(hostName)
    is SessionState.AwaitingApproval -> ScreenState.AwaitingApproval(request.presentation(), hostName, hostKeyId)
    is SessionState.AwaitingBiometric -> ScreenState.AwaitingBiometric(request.presentation(), hostName, hostKeyId)
    is SessionState.Approved -> ScreenState.Approved(request.presentation(), hostName, hostKeyId)
    is SessionState.Denied -> ScreenState.Denied(requestId, reason)
    is SessionState.Failed -> ScreenState.Failed(message)
}
