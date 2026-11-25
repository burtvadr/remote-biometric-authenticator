package io.github.burtvadr.rba.runtime

import android.content.Context
import android.content.Intent
import android.os.SystemClock
import androidx.core.content.ContextCompat
import io.github.burtvadr.rba.service.V2BackgroundService
import io.github.burtvadr.rba.transport.V2ConnectionOwner
import io.github.burtvadr.rba.session.V2DeviceStore
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.UUID

/** Foreground launch and notification permission enable discovery of enrolled endpoints. No network endpoint
 * or credential is obtained from an Intent, notification or remote peer.
 * Process death stops listening; no silent background restart or boot route. */
internal object V2BackgroundRuntime {
    class Selection(val routes:List<V2DeviceStore.Route>) {
        val startId=UUID.randomUUID().toString()
        val gate=V2NotificationGate<V2ConnectionOwner.Ui>(SystemClock::elapsedRealtime)
        var claimed=false
    }
    @Volatile private var selection:Selection?=null
    private val mutableRunning=MutableStateFlow(false)
    private val mutableConnected=MutableStateFlow<String?>(null)
    val connectedState=mutableConnected.asStateFlow()
    @Volatile private var stoppedByUser=false
    fun allowForegroundStart(){stoppedByUser=false}
    fun userStopped(){stoppedByUser=true}
    fun startAllowed()=!stoppedByUser
    fun routes():List<V2DeviceStore.Route>?=selection?.routes
    @Synchronized fun connected(s:Selection,host:String?){if(selection===s)mutableConnected.value=host}
    val runningState=mutableRunning.asStateFlow()
    private fun set(s:Selection?){selection=s;mutableRunning.value=s!=null;mutableConnected.value=null}
    fun running()=selection!=null
    @Synchronized fun start(context:Context,routes:List<V2DeviceStore.Route>) {
        check(selection==null && startAllowed())
        require(routes.size in 1..64 && routes.any{it.summary.state==V2DeviceStore.RecordState.ACTIVE})
        val s=Selection(routes.toList());set(s)
        // Only a generation locator; persisted credential routes are not Intent data.
        try{ContextCompat.startForegroundService(context,Intent(context,V2BackgroundService::class.java).setAction(s.startId))}
        catch(e:Exception){set(null);throw e}
    }
    @Synchronized fun claim(startId:String?):Selection? {
        val s=selection?:return null
        if(s.claimed||s.startId!=startId)return null
        s.claimed=true;return s
    }
    @Synchronized fun ended(s:Selection) {
        if(selection===s){s.gate.stop();set(null)}
    }
    @Synchronized fun stop(context:Context) {
        val s=selection?:return
        s.gate.stop()
        // If start has not yet been delivered, discard the selection. A late
        // service start cannot claim another endpoint or an old request.
        if(!s.claimed)set(null)
        context.stopService(Intent(context,V2BackgroundService::class.java))
    }
    fun attach(token:String,ui:V2ConnectionOwner.Ui)=selection?.gate?.attach(token,ui)==true
    fun abandon(token:String){selection?.gate?.abandon(token)}
}
