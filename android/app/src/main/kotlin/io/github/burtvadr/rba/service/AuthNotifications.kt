package io.github.burtvadr.rba.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import io.github.burtvadr.rba.MainActivity
import io.github.burtvadr.rba.R
import io.github.burtvadr.rba.runtime.OperatorLaunch
import io.github.burtvadr.rba.runtime.OperatorRequestKind

/**
 * All notifications in one place.
 *
 * The ongoing notification is deliberately quiet: it keeps the process alive while
 * the link is idle. The request notification is the fallback path when Android
 * refuses a background activity start; its full-screen intent is the strongest
 * thing an ordinary app can do to put a prompt in front of the operator.
 */
object AuthNotifications {

    private const val CHANNEL_ONGOING = "auth-service"
    private const val CHANNEL_REQUESTS = "auth-requests"

    const val ONGOING_ID = 0x1001
    const val REQUEST_ID = 0x1002

    fun ensureChannels(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = context.getSystemService(NotificationManager::class.java) ?: return

        val ongoing = NotificationChannel(
            CHANNEL_ONGOING,
            "Background operation",
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = "Keeps the link to your host open while it is idle."
            setShowBadge(false)
            setSound(null, null)
        }

        val requests = NotificationChannel(
            CHANNEL_REQUESTS,
            "Authentication requests",
            NotificationManager.IMPORTANCE_HIGH,
        ).apply {
            description = "Shown when a host asks for a fingerprint confirmation."
            lockscreenVisibility = Notification.VISIBILITY_PRIVATE
            setShowBadge(true)
            setSound(null, null)
            enableVibration(false)
        }

        manager.createNotificationChannels(listOf(ongoing, requests))
    }

    /** The ongoing notification that keeps the foreground service alive. */
    fun ongoing(context: Context): Notification {
        ensureChannels(context)
        val open = PendingIntent.getActivity(
            context,
            0,
            Intent(context, MainActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val stop = PendingIntent.getService(
            context,
            1,
            Intent(context, AuthService::class.java).setAction(AuthService.ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(context, CHANNEL_ONGOING)
            .setSmallIcon(R.drawable.ic_stat_authenticator)
            .setContentTitle("Remote authenticator")
            .setContentText("Waiting for your host")
            .setContentIntent(open)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .setShowWhen(false)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .addAction(0, "Stop", stop)
            .build()
    }

    /**
     * Asks the operator to look at the device, without putting request details on
     * the lock screen. The activity shows the signed context.
     */
    fun showRequest(context: Context, kind: OperatorRequestKind) {
        ensureChannels(context)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            context.checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) !=
            android.content.pm.PackageManager.PERMISSION_GRANTED
        ) {
            // The overlay/full-screen activity path does not need this permission.
            return
        }
        val intent = OperatorLaunch.intent(context, kind)
        val pending = PendingIntent.getActivity(
            context,
            100 + kind.ordinal,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val title = when (kind) {
            OperatorRequestKind.AUTHENTICATION -> "Authentication requested"
            OperatorRequestKind.PAIRING -> "Pairing requested"
        }
        val text = when (kind) {
            OperatorRequestKind.AUTHENTICATION -> "Tap to confirm with your fingerprint"
            OperatorRequestKind.PAIRING -> "Tap to compare the pairing code"
        }
        val notification = NotificationCompat.Builder(context, CHANNEL_REQUESTS)
            .setSmallIcon(R.drawable.ic_stat_authenticator)
            .setContentTitle(title)
            .setContentText(text)
            .setContentIntent(pending)
            .setFullScreenIntent(pending, true)
            .setCategory(NotificationCompat.CATEGORY_EVENT)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setAutoCancel(true)
            .setTimeoutAfter(45_000L)
            .build()
        runCatching {
            NotificationManagerCompat.from(context).notify(REQUEST_ID, notification)
        }
    }

    fun clearRequest(context: Context) {
        runCatching { NotificationManagerCompat.from(context).cancel(REQUEST_ID) }
    }
}
