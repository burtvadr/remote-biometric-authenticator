package io.github.burtvadr.rba.ui.v2

import android.app.KeyguardManager
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import io.github.burtvadr.rba.service.AppSettings
import io.github.burtvadr.rba.ui.theme.AppTheme
import io.github.burtvadr.rba.ui.theme.FingerprintBadge
import androidx.fragment.app.FragmentActivity
import io.github.burtvadr.rba.runtime.V2BackgroundRuntime

/** The only notification handoff UI. Opening the activity does not approve
 * a request. An expired, stale or already consumed locator cannot attach. */
class V2NotificationActivity : FragmentActivity() {
    private var attached:String?=null
    private var attempted=false
    override fun onCreate(savedInstanceState:Bundle?){
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        setContent {
            AppTheme(AppSettings.themeMode(this),AppSettings.dynamicColor(this)){
                Surface(Modifier.fillMaxSize()){
                    Column(Modifier.padding(20.dp),horizontalAlignment=Alignment.CenterHorizontally,verticalArrangement=Arrangement.spacedBy(16.dp)){
                        FingerprintBadge(style=AppSettings.iconStyle(this@V2NotificationActivity),size=76.dp)
                        Text("Authentication request",style=MaterialTheme.typography.headlineSmall)
                        Text("Review the live authentication request. Close this screen to cancel.",style=MaterialTheme.typography.bodyMedium)
                    }
                }
            }
        }
    }
    override fun onResume(){
        super.onResume()
        if(attempted){if(attached==null)finish();return};attempted=true
        val uri=intent.data
        val token=uri?.lastPathSegment
        val unlocked=!getSystemService(KeyguardManager::class.java).isDeviceLocked
        if(!unlocked || uri==null || uri.scheme!="rba-v2-review" || uri.authority!="local" || token==null ||
            !V2BackgroundRuntime.attach(token,V2ReviewDialogs(this))){finish();return}
        attached=token
    }
    override fun onStop(){attached?.let{V2BackgroundRuntime.abandon(it)};attached=null;super.onStop();finish()}
}
