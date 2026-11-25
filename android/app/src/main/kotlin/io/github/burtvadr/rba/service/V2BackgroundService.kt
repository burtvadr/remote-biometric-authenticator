package io.github.burtvadr.rba.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.Uri
import android.os.Build
import android.os.IBinder
import androidx.core.app.ServiceCompat
import io.github.burtvadr.rba.R
import io.github.burtvadr.rba.runtime.V2BackgroundRuntime
import io.github.burtvadr.rba.runtime.V2ForegroundRuntime
import io.github.burtvadr.rba.runtime.V2NotificationGate
import io.github.burtvadr.rba.transport.V2ConnectionOwner
import io.github.burtvadr.rba.ui.v2.V2NotificationActivity
import kotlinx.coroutines.*
import java.util.UUID

/** An explicitly enabled, single-endpoint listener, not a second runtime.
 * Start only from the V2 foreground activity. No boot start, alarm, overlay,
 * full-screen intent, automatic biometric prompt or approval action. */
class V2BackgroundService : Service() {
    private val scope=CoroutineScope(SupervisorJob()+Dispatchers.Main.immediate)
    private var selected:V2BackgroundRuntime.Selection?=null
    private val nm get()=getSystemService(NotificationManager::class.java)
    override fun onBind(intent:Intent?):IBinder?=null
    override fun onStartCommand(intent:Intent?,flags:Int,startId:Int):Int {
        if(intent?.action==STOP){
            if(selected?.startId==intent.data?.lastPathSegment && selected!=null)stopSelf()
            else if(selected==null)stopSelf(startId)
            return START_NOT_STICKY
        }
        if(selected!=null)return START_NOT_STICKY
        val s=V2BackgroundRuntime.claim(intent?.action)?:run{stopSelf(startId);return START_NOT_STICKY}
        selected=s
        try{
            nm.createNotificationChannel(NotificationChannel(ONGOING,"RBA listener",NotificationManager.IMPORTANCE_LOW))
            nm.createNotificationChannel(NotificationChannel(REVIEW,"RBA authentication review",NotificationManager.IMPORTANCE_HIGH).apply{lockscreenVisibility=Notification.VISIBILITY_SECRET})
            check(notificationsAvailable())
            val type=if(Build.VERSION.SDK_INT>=34)ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE else 0
            ServiceCompat.startForeground(this,ONGOING_ID,ongoing(s),type)
        }catch(_:Exception){stopSelf();return START_NOT_STICKY}
        scope.launch {listen(s)}
        return START_NOT_STICKY
    }
    private fun notificationsAvailable()=nm.areNotificationsEnabled() &&
        listOf(ONGOING,REVIEW).all{(nm.getNotificationChannel(it)?.importance?:NotificationManager.IMPORTANCE_NONE)>NotificationManager.IMPORTANCE_NONE}
    private fun ongoing(s:V2BackgroundRuntime.Selection):Notification {
        val intent=Intent(this,V2BackgroundService::class.java).setAction(STOP)
            .setData(Uri.Builder().scheme("rba-v2-stop").authority("local").appendPath(s.startId).build())
        val stop=PendingIntent.getService(this,0,intent,PendingIntent.FLAG_IMMUTABLE)
        return Notification.Builder(this,ONGOING).setSmallIcon(R.drawable.ic_stat_authenticator)
            .setContentTitle("RBA listener enabled").setContentText("Waiting for an authenticated host request")
            .setOngoing(true).setVisibility(Notification.VISIBILITY_SECRET)
            .addAction(Notification.Action.Builder(R.drawable.ic_stat_authenticator,"Stop listener",stop).build()).build()
    }
    private fun review(token:String,remaining:Long):Notification {
        val intent=Intent(this,V2NotificationActivity::class.java)
            .setData(Uri.Builder().scheme("rba-v2-review").authority("local").appendPath(token).build())
        val open=PendingIntent.getActivity(this,0,intent,PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_ONE_SHOT)
        return Notification.Builder(this,REVIEW).setSmallIcon(R.drawable.ic_stat_authenticator)
            .setContentTitle("Authentication review available")
            .setContentText("Unlock and open RBA to review. Nothing has been approved.")
            .setVisibility(Notification.VISIBILITY_SECRET).setAutoCancel(true).setContentIntent(open)
            .setTimeoutAfter(remaining).build()
    }
    private suspend fun listen(s:V2BackgroundRuntime.Selection) {
        try{
            while(currentCoroutineContext().isActive && notificationsAvailable()) {
                // Child cancellation (decline/activity stops) must not cancel
                // the explicitly enabled listener. Service cancellation does.
                supervisorScope {
                    val attempt=async {
                        val job=currentCoroutineContext().job
                        var ticket:V2NotificationGate.Ticket<V2ConnectionOwner.Ui>?=null
                        try{
                            V2ForegroundRuntime.awaitAuthentication(applicationContext,s.host,s.port,s.credential){deadline->
                                // Serialize publication with service destruction on Main.
                                withContext(Dispatchers.Main.immediate){
                                    ensureActive();check(notificationsAvailable() && selected===s)
                                    val t=s.gate.open(UUID.randomUUID().toString(),deadline,job);ticket=t
                                    val remaining=deadline-android.os.SystemClock.elapsedRealtime();check(remaining>0)
                                    nm.notify(s.startId,REVIEW_ID,review(t.token,remaining))
                                    t.await().also{nm.cancel(s.startId,REVIEW_ID)}
                                }
                            }
                        }finally{
                            // Scope cancellation must remove the exact old
                            // notification and dismiss only its attached UI.
                            val ui=ticket?.let{s.gate.release(it)}
                            withContext(NonCancellable+Dispatchers.Main.immediate){
                                nm.cancel(s.startId,REVIEW_ID);ui?.activity?.finish()
                            }
                        }
                    }
                    try{attempt.await()}catch(e:CancellationException){currentCoroutineContext().ensureActive()}
                    catch(_:Exception){/* generic failure; no secret logs or automatic trust reset */}
                }
                // Even instant failures use a fixed cooldown: at most six
                // connection starts per rolling minute for this listener.
                delay(10000)
            }
        }finally{stopSelf()}
    }
    override fun onDestroy(){
        selected?.let{it.gate.stop();nm.cancel(it.startId,REVIEW_ID);V2BackgroundRuntime.ended(it)};selected=null
        scope.cancel()
        ServiceCompat.stopForeground(this,ServiceCompat.STOP_FOREGROUND_REMOVE)
        super.onDestroy()
    }
    companion object {
        private const val ONGOING="rba-v2-listener"
        private const val REVIEW="rba-v2-review"
        private const val ONGOING_ID=2201
        private const val REVIEW_ID=2202
        private const val STOP="io.github.burtvadr.rba.v2.STOP_LISTENER"
    }
}
