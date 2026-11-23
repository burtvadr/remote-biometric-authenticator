package io.github.burtvadr.rba.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * Restarts the background link after a reboot, but only if the user left it on.
 *
 * The service is not started for any other broadcast: a boot receiver that reacts
 * to everything is a battery bug with extra steps.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        if (!AppSettings.backgroundEnabled(context)) return
        try {
            AuthService.start(context)
        } catch (e: Exception) {
            Log.w("BootReceiver", "cannot restart the authenticator: ${e.message}")
        }
    }
}
