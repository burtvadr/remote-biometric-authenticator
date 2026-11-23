package io.github.burtvadr.rba.service

import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import io.github.burtvadr.rba.runtime.AuthenticatorRuntime

/**
 * Keeps the host link alive while the activity is not on screen.
 *
 * The service owns no protocol state of its own: it asks [AuthenticatorRuntime]
 * for the process-wide session and keeps Android from killing the process while a
 * request can still arrive. The ongoing notification is quiet; request
 * notifications are posted by the runtime.
 */
class AuthService : Service() {

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        AuthNotifications.ensureChannels(this)
        // Foreground before the potentially slower keystore/session setup, so the
        // five-second startForeground deadline is never at the mercy of key storage.
        startInForeground()
        AuthenticatorRuntime.start(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            AppSettings.setBackgroundEnabled(this, false)
            AuthenticatorRuntime.stop("background operation was turned off")
            AuthNotifications.clearRequest(this)
            ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }

        AppSettings.setBackgroundEnabled(this, true)
        AuthenticatorRuntime.start(this)
        startInForeground()
        return START_STICKY
    }

    override fun onDestroy() {
        if (!AuthenticatorRuntime.activityVisible) {
            AuthenticatorRuntime.stop("the background service stopped")
        }
        super.onDestroy()
    }

    private fun startInForeground() {
        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        } else {
            0
        }
        try {
            ServiceCompat.startForeground(
                this,
                AuthNotifications.ONGOING_ID,
                AuthNotifications.ongoing(this),
                type,
            )
        } catch (e: Exception) {
            // A denied notification permission or an OEM foreground-service policy
            // must not take the app down; the activity can still be used normally.
            Log.w(TAG, "cannot enter the foreground: ${e.message}")
        }
    }

    companion object {
        private const val TAG = "AuthService"
        const val ACTION_STOP = "io.github.burtvadr.rba.action.STOP"

        fun start(context: Context) {
            runCatching {
                ContextCompat.startForegroundService(
                    context,
                    Intent(context, AuthService::class.java),
                )
            }.onFailure { Log.w(TAG, "cannot start the service: ${it.message}") }
        }
    }
}
