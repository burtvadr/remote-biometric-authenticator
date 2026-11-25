package io.github.burtvadr.rba.ui.v2

import android.app.KeyguardManager
import android.os.Bundle
import android.view.WindowManager
import android.widget.TextView
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
        setContentView(TextView(this).apply{text="Review the live authentication request. Close this screen to cancel.";setPadding(24,24,24,24)})
    }
    override fun onResume(){
        super.onResume()
        if(attempted){if(attached==null)finish();return};attempted=true
        val uri=intent.data
        val token=uri?.lastPathSegment
        val unlocked=!getSystemService(KeyguardManager::class.java).isDeviceLocked
        if(!unlocked || uri==null || uri.scheme!="rba-v2-review" || uri.authority!="local" || token==null ||
            !V2BackgroundRuntime.attach(token,V2OperatorDialogs(this))){finish();return}
        attached=token
    }
    override fun onStop(){attached?.let{V2BackgroundRuntime.abandon(it)};attached=null;super.onStop();finish()}
}
