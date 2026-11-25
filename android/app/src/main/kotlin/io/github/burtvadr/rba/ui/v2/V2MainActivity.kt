package io.github.burtvadr.rba.ui.v2

import android.Manifest
import android.app.NotificationManager
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.biometric.BiometricManager
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import io.github.burtvadr.rba.BuildConfig
import io.github.burtvadr.rba.DeviceIdentity
import io.github.burtvadr.rba.appearance.AppIconController
import io.github.burtvadr.rba.appearance.ThemeMode
import io.github.burtvadr.rba.keystore.V2HardwareKeys
import io.github.burtvadr.rba.runtime.V2BackgroundRuntime
import io.github.burtvadr.rba.runtime.V2ForegroundRuntime
import io.github.burtvadr.rba.runtime.V2ForegroundRuntime.Operation
import io.github.burtvadr.rba.service.AppSettings
import io.github.burtvadr.rba.session.V2DeviceStore
import io.github.burtvadr.rba.transport.V2Discovery
import io.github.burtvadr.rba.transport.V2DiscoveryHint
import io.github.burtvadr.rba.ui.*
import io.github.burtvadr.rba.ui.theme.AppTheme
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.security.MessageDigest

/** Original Compose product surface, backed exclusively by V2. Discovery
 * supplies candidates; the V2 operation owner alone decides trust and results. */
class V2MainActivity : FragmentActivity() {
    private var screen by mutableStateOf<ScreenState>(ScreenState.Idle)
    private var hosts by mutableStateOf<List<HostPresentation>>(emptyList())
    private var visibleKeys by mutableStateOf<Set<String>>(emptySet())
    private var security by mutableStateOf<SecurityPresentation?>(null)
    private var background by mutableStateOf(BackgroundStatus(false,false,false,false,true))
    private val operations=Mutex()
    private val attempted=linkedSetOf<String>()
    private val maintenanceAttempts=mutableMapOf<String,Long>()
    private val reviews by lazy { V2ReviewDialogs(this) }
    private val permission=registerForActivityResult(ActivityResultContracts.RequestPermission()){refreshPermissions()}
    private val labels get()=getSharedPreferences("rba-v2-presentation",MODE_PRIVATE)

    override fun onCreate(savedInstanceState:Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        V2BackgroundRuntime.allowForegroundStart()
        var theme by mutableStateOf(AppSettings.themeMode(this))
        var icon by mutableStateOf(AppSettings.iconStyle(this))
        var dynamic by mutableStateOf(AppSettings.dynamicColor(this))
        AppIconController.apply(this,icon,dark(theme))
        val deviceId=DeviceIdentity.load(this).toHex() // display identity only; never a credential
        val deviceName=DeviceIdentity.name(this)
        refreshPermissions()
        setContent {
            AppTheme(themeMode=theme,dynamicColor=dynamic) {
                val connected by V2BackgroundRuntime.connectedState.collectAsStateWithLifecycle()
                AuthenticatorScreen(
                    state=screen, deviceId=deviceId, deviceName=deviceName, capabilities=security,
                    hosts=hosts,connectedHostId=connected,discoveredKeyIds=visibleKeys,background=background,
                    themeMode=theme,iconStyle=icon,dynamicColor=dynamic,
                    onThemeModeChange={theme=it;AppSettings.setThemeMode(this@V2MainActivity,it);AppIconController.apply(this@V2MainActivity,icon,dark(it))},
                    onIconStyleChange={icon=it;AppSettings.setIconStyle(this@V2MainActivity,it);AppIconController.apply(this@V2MainActivity,it,dark(theme))},
                    onDynamicColorChange={dynamic=it;AppSettings.setDynamicColor(this@V2MainActivity,it)},
                    // V2's live operation owner drives protected code/consent dialogs;
                    // the former V1 callbacks cannot approve a V2 operation.
                    onConfirmPairing={false},onRejectPairing={},
                    onForgetHost=::forgetHost,onFixNotifications=::notifications,
                    onFixOverlay={},onFixBattery=::applicationSettings,onFixFullScreen={},
                    versionName=BuildConfig.VERSION_NAME,isDebug=BuildConfig.DEBUG,
                )
            }
        }
        if(!AppSettings.notificationAsked(this)){
            AppSettings.setNotificationAsked(this,true)
            if(Build.VERSION.SDK_INT>=33&&!background.notificationsAllowed)permission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED){
                while(isActive){
                    try{
                        operations.withLock{tick()}
                    }catch(e:CancellationException){throw e}
                    catch(_:Exception){
                        // Do not manufacture an empty inventory on a failed store read.
                        screen=ScreenState.Failed("RBA could not open or use its protected state. Existing records were not reset.")
                        delay(2500);screen=ScreenState.Idle
                    }
                    delay(2000)
                }
            }
        }
    }
    override fun onResume(){super.onResume();refreshPermissions()}
    private fun dark(mode:ThemeMode)=when(mode){
        ThemeMode.DARK->true;ThemeMode.LIGHT->false
        ThemeMode.SYSTEM->resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK==Configuration.UI_MODE_NIGHT_YES
    }
    private fun refreshPermissions(){
        val notification=getSystemService(NotificationManager::class.java).areNotificationsEnabled() &&
            (Build.VERSION.SDK_INT<33||ContextCompat.checkSelfPermission(this,Manifest.permission.POST_NOTIFICATIONS)==PackageManager.PERMISSION_GRANTED)
        background=BackgroundStatus(notification,false,getSystemService(PowerManager::class.java).isIgnoringBatteryOptimizations(packageName),false,true)
    }
    private fun notifications(){
        if(Build.VERSION.SDK_INT>=33&&ContextCompat.checkSelfPermission(this,Manifest.permission.POST_NOTIFICATIONS)!=PackageManager.PERMISSION_GRANTED)permission.launch(Manifest.permission.POST_NOTIFICATIONS)
        else startActivity(Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE,packageName))
    }
    private fun applicationSettings(){startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,Uri.parse("package:$packageName")))}
    private fun hash(point:ByteArray)=MessageDigest.getInstance("SHA-256").digest(point).joinToString(""){"%02x".format(it.toInt() and 255)}
    private fun id(hex:String)=hex.chunked(2).map{it.toInt(16).toByte()}.toByteArray()
    private fun endpoint(route:V2DeviceStore.Route,hints:List<V2DiscoveryHint>)=V2DiscoveryHint.enrolled(hints,id(route.summary.host),route.hostPoint)
    private suspend fun routes()=V2BackgroundRuntime.routes()?:V2ForegroundRuntime.routes(applicationContext)
    private fun present(records:List<V2DeviceStore.Route>,hints:List<V2DiscoveryHint>){
        val active=records.filter{it.summary.state==V2DeviceStore.RecordState.ACTIVE}
        check(active.groupBy{it.summary.host}.values.all{r->r.map{hash(it.hostPoint)}.distinct().size==1})
        hosts=active.groupBy{it.summary.host}.map{(host,recordsForHost)->
            val route=recordsForHost.first()
            val key=hash(route.hostPoint)
            HostPresentation(host,key,labels.getString("host:$host:$key",null)?:"Host ${host.take(8)}",true)
        }
        visibleKeys=active.mapNotNull{r->endpoint(r,hints)?.keyHash}.toSet()
        val location=active.firstNotNullOfOrNull{it.location}
        security=SecurityPresentation(when(location){
            V2HardwareKeys.Location.STRONGBOX->KeyStoragePresentation.STRONGBOX
            V2HardwareKeys.Location.TEE,V2HardwareKeys.Location.HARDWARE->KeyStoragePresentation.HARDWARE
            null->null
        },BiometricManager.from(this).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)==BiometricManager.BIOMETRIC_SUCCESS)
    }
    private suspend fun stopListener(){
        V2BackgroundRuntime.stop(applicationContext)
        withTimeout(5000L){V2BackgroundRuntime.runningState.first{!it}}
    }
    private fun startListener(records:List<V2DeviceStore.Route>){
        if(background.notificationsAllowed&&V2BackgroundRuntime.startAllowed()&&!V2BackgroundRuntime.running()&&records.any{it.summary.state==V2DeviceStore.RecordState.ACTIVE})
            V2BackgroundRuntime.start(applicationContext,records)
    }
    private suspend fun tick(){
        var records=routes()
        val hints=try{V2Discovery.scan(applicationContext)}catch(e:CancellationException){throw e}catch(_:Exception){emptyList()}
        present(records,hints)
        val pair=V2DiscoveryHint.pairing(hints)
        if(pair!=null&&attempted.add(pair.attempt)){
            while(attempted.size>64)attempted.remove(attempted.first())
            screen=ScreenState.PairingAwaitingCode("Nearby host")
            try{
                if(!reviews.confirmDiscoveredPairing(pair.label)){startListener(records);return}
                stopListener()
                // Local foreground operation, original PAKE and exact review
                // still mandatory. An advertisement cannot approve enrollment.
                // Only locally disabled, matching-host records qualify. The
                // live PAKE owner checks the actual host and requires explicit
                // cleanup review before transmitting any revocation tokens.
                val cleanup=records.filter{it.summary.state==V2DeviceStore.RecordState.REVOKING&&it.summary.host==pair.hostId&&hash(it.hostPoint)==pair.keyHash}.map{it.summary.credential}
                check(cleanup.size<=32)
                V2ForegroundRuntime.operate(applicationContext,pair.address,pair.port,Operation.ENROLL,null,cleanup,reviews)
                records=routes()
                val enrolled=records.firstOrNull{it.summary.state==V2DeviceStore.RecordState.ACTIVE&&it.summary.host==pair.hostId&&hash(it.hostPoint)==pair.keyHash}
                if(enrolled!=null)labels.edit().putString("host:${pair.hostId}:${pair.keyHash}",pair.label).apply()
                present(records,hints)
                screen=ScreenState.PairingConfirmed(if(enrolled!=null)pair.label else "Verified host")
                delay(700)
            }catch(e:CancellationException){throw e}
            catch(_:Exception){screen=ScreenState.Failed("Pairing not completed. Check the host terminal before retrying.");delay(1800)}
            finally{screen=ScreenState.Idle}
            // An interrupted receipt can leave a durable PENDING record. Reload
            // before a new listener captures the inventory snapshot.
            records=routes();present(records,hints)
        }else{
            // Recovery finishes an already approved staged receipt; revocation
            // retry only completes an already committed local denial.
            val now=android.os.SystemClock.elapsedRealtime()
            val retry=records.firstOrNull{r->r.summary.state in listOf(V2DeviceStore.RecordState.PENDING,V2DeviceStore.RecordState.REVOKING)&&
                now-(maintenanceAttempts[r.summary.credential]?:-60000L)>=60000L&&endpoint(r,hints)!=null}
            if(retry!=null){
                val target=checkNotNull(endpoint(retry,hints));maintenanceAttempts[retry.summary.credential]=now
                stopListener()
                try{V2ForegroundRuntime.operate(applicationContext,target.address,target.port,
                    if(retry.summary.state==V2DeviceStore.RecordState.PENDING)Operation.RECOVER else Operation.REVOKE,retry.summary.credential,emptyList(),reviews)}
                catch(e:CancellationException){throw e}catch(_:Exception){/* preserve durable state */}
                records=routes();present(records,hints)
            }
        }
        startListener(records)
    }
    private fun forgetHost(hostId:String):Boolean {
        if(hosts.none{it.hostId==hostId})return false
        lifecycleScope.launch {
            operations.withLock {
                try{
                    stopListener()
                    V2ForegroundRuntime.revokeHostLocally(applicationContext,hostId)
                    val records=routes();present(records,emptyList());startListener(records)
                }catch(e:CancellationException){throw e}
                catch(_:Exception){screen=ScreenState.Failed("Unpairing could not be completed. Check the host before retrying.");delay(1800);screen=ScreenState.Idle}
            }
        }
        return true // schedules locally confirmed denial, never claims network receipt
    }
}
