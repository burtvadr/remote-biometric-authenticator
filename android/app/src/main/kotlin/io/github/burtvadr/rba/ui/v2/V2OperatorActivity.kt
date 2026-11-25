package io.github.burtvadr.rba.ui.v2

import android.app.AlertDialog
import android.os.Bundle
import android.text.InputType
import android.view.WindowManager
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.repeatOnLifecycle
import io.github.burtvadr.rba.runtime.V2BackgroundRuntime
import io.github.burtvadr.rba.runtime.V2ForegroundRuntime
import io.github.burtvadr.rba.runtime.V2ForegroundRuntime.Operation
import io.github.burtvadr.rba.session.V2DeviceStore
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.collect

/** Definitive foreground entry point for the V2 cutover. No routing by intent
 * extras; local selection is mandatory. Registered exclusively in the V2 candidate manifest. */
class V2OperatorActivity : FragmentActivity() {
    private lateinit var status: TextView
    private lateinit var host: EditText
    private lateinit var port: EditText
    private lateinit var records: LinearLayout
    private lateinit var controls: LinearLayout
    private lateinit var cancel: Button
    private var task: Job? = null
    private var selected: V2DeviceStore.Summary? = null
    private val cleanup = linkedSetOf<String>()
    private var summaries = emptyList<V2DeviceStore.Summary>()
    private val ui by lazy { V2OperatorDialogs(this) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        val body = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(24, 16, 24, 16) }
        body.addView(TextView(this).apply { text = "RBA · Protocol V2"; textSize = 24f })
        status = TextView(this).also { body.addView(it) }
        host = EditText(this).apply { hint = "Host address"; inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI; isSaveEnabled = false }
        port = EditText(this).apply { hint = "Host listener port"; inputType = InputType.TYPE_CLASS_NUMBER; isSaveEnabled = false }
        body.addView(host); body.addView(port)
        controls = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        body.addView(controls)
        records = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        body.addView(records)
        cancel = Button(this).apply { text = "Cancel operation"; isEnabled = false; setOnClickListener { task?.cancel() } }
        body.addView(cancel)
        setContentView(ScrollView(this).apply { addView(body) })
        drawControls()
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                V2BackgroundRuntime.runningState.collect { running ->
                    if(running) status.text="Background listener enabled. Stop it to manage credentials."
                    else if(task==null) status.text="Listener stopped. Refresh credentials if needed."
                    drawControls()
                }
            }
        }
    }
    override fun onStart() {
        super.onStart()
        if (V2BackgroundRuntime.running()) { status.text = "Background listener enabled. Stop it to manage credentials."; drawControls() }
        else if (task?.isActive != true) launchTask { reload(); "Select a local operation." }
    }
    override fun onStop() {
        // The foreground path never carries approval across backgrounding or
        // recreation, including when no prompt dialog is currently visible.
        task?.cancel()
        super.onStop()
    }
    private fun button(title: String, enabled: Boolean = true, action: () -> Unit) {
        controls.addView(Button(this).apply { text = title; filterTouchesWhenObscured = true; isEnabled = enabled; setOnClickListener { action() } })
    }
    private fun drawControls() {
        controls.removeAllViews(); records.removeAllViews()
        val listening=V2BackgroundRuntime.running()
        val idle = task == null && !listening
        host.isEnabled = idle; port.isEnabled = idle; cancel.isEnabled = task != null
        val current = selected
        button("Initialize new V2 store", idle) {
            AlertDialog.Builder(this).setTitle("Initialize V2 storage")
                .setMessage("Only creates a new store. Existing, missing or corrupt enrollment records are never reset. Continue only for a fresh installation.")
                .setNegativeButton("Cancel", null).setPositiveButton("Initialize") { _, _ ->
                    launchTask { V2ForegroundRuntime.initialize(applicationContext); reload(); "V2 store initialized" }
                }.show()
        }
        button("Refresh credentials", idle) { launchTask { reload(); "Credential list refreshed" } }
        button("Enroll at selected host (include checked cleanup records)", idle) { runOperation(Operation.ENROLL) }
        val active = current?.state == V2DeviceStore.RecordState.ACTIVE
        button("Enable background listener for selected credential", idle && active) {
            if(android.os.Build.VERSION.SDK_INT>=33 && checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS)!=android.content.pm.PackageManager.PERMISSION_GRANTED){
                requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS),2201)
                status.text="Notification permission required. Enable the listener again after granting it."
            }else try {
                V2BackgroundRuntime.start(applicationContext,host.text.toString().trim(),port.text.toString().toIntOrNull()?:0,checkNotNull(current).credential)
                status.text="Background listener requested. No request is approved automatically.";drawControls()
            }catch(_:Exception){status.text="Listener could not start."}
        }
        button("Stop background listener", listening) {
            V2BackgroundRuntime.stop(applicationContext)
            status.text="Stopping listener. Return to this screen or refresh after it stops."
            // The lifecycle-aware collector redraws only on the actual state transition.
        }
        button("Authenticate selected credential", idle && active) { runOperation(Operation.AUTHENTICATE) }
        button("Synchronize selected policy", idle && active) { runOperation(Operation.POLICY) }
        button("Recover selected pending enrollment", idle && current?.state == V2DeviceStore.RecordState.PENDING) { runOperation(Operation.RECOVER) }
        button("Revoke / retry selected credential", idle && current != null && current.state != V2DeviceStore.RecordState.PENDING) {
            AlertDialog.Builder(this).setTitle("Disable credential locally")
                .setMessage("Credential ${current?.credential}\nThis immediately disables local authentication even if the host is unreachable.")
                .setNegativeButton("Cancel", null).setPositiveButton("Revoke") { _, _ -> runOperation(Operation.REVOKE) }.show()
        }
        records.addView(TextView(this).apply { text = "Recorded credentials (not a hardware-health check)" })
        for (record in summaries) {
            records.addView(Button(this).apply {
                text = "${if (selected == record) "Selected · " else ""}${record.state}\nHost ${record.host}\nCredential ${record.credential}"
                isEnabled = idle
                setOnClickListener { selected = record; drawControls() }
            })
            if (record.state == V2DeviceStore.RecordState.REVOKING) records.addView(CheckBox(this).apply {
                text = "Include ${record.credential} in same-host cleanup"; isChecked = record.credential in cleanup; isEnabled = idle
                setOnCheckedChangeListener { _, checked -> if (checked) cleanup.add(record.credential) else cleanup.remove(record.credential) }
            })
        }
    }
    private suspend fun reload() {
        summaries = V2ForegroundRuntime.inventory(applicationContext)
        selected = summaries.firstOrNull { it.credential == selected?.credential }
        cleanup.retainAll(summaries.filter { it.state == V2DeviceStore.RecordState.REVOKING }.map { it.credential }.toSet())
    }
    private fun runOperation(operation: Operation) {
        val address = host.text.toString().trim()
        val listener = port.text.toString().toIntOrNull() ?: 0
        val credential = if (operation == Operation.ENROLL) null else selected?.credential
        val selectedCleanup = if (operation == Operation.ENROLL) cleanup.toList() else emptyList()
        launchTask {
            V2ForegroundRuntime.operate(applicationContext, address, listener, operation, credential, selectedCleanup, ui)
        }
    }
    private fun launchTask(work: suspend () -> String) {
        if (task != null) return
        // Lazy start installs the Job before the body can complete or render.
        task = lifecycleScope.launch(start = kotlinx.coroutines.CoroutineStart.LAZY) {
            try { status.text = work(); reload() }
            catch (e: CancellationException) { summaries = emptyList(); selected = null; cleanup.clear(); status.text = "Operation cancelled; committed records remain authoritative."; throw e }
            catch (_: Exception) {
                summaries = emptyList(); selected = null; cleanup.clear()
                status.text = "Operation rejected or incomplete. Refresh credentials before retrying. No automatic reset."
            }
            finally {
                // Never update or restore trust on a cancelled operation.
                task = null
                drawControls()
            }
        }
        status.text = "Working…"; drawControls(); task?.start()
    }
}
