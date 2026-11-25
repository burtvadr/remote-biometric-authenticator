package io.github.burtvadr.rba.ui.v2

import android.app.AlertDialog
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.fragment.app.FragmentActivity
import io.github.burtvadr.rba.protocol.Cbor
import io.github.burtvadr.rba.protocol.V2Enrollment
import io.github.burtvadr.rba.protocol.V2Message
import io.github.burtvadr.rba.transport.V2ConnectionOwner
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

/** One cancellable interaction at a time, invoked on the main thread by the
 * operation owner. Dialog dismissal is denial, never approval. */
internal class V2ReviewDialogs(override val activity: FragmentActivity) : V2ConnectionOwner.Ui {
    private suspend fun ask(title: String, facts: String, digits: Boolean = false, positive: String = "Approve"): String? =
        suspendCancellableCoroutine { c ->
            val content = LinearLayout(activity).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(24, 12, 24, 12)
                addView(TextView(activity).apply { text = facts; setTextIsSelectable(false) })
            }
            // Local keypad: no IME, clipboard, autofill or saved view state.
            val buffer = CharArray(6)
            var length = 0
            fun erase() { buffer.fill('\u0000'); length = 0 }
            if (digits) {
                val count = TextView(activity).apply { text = "0 / 6 digits" }
                content.addView(count)
                fun render() { count.text = "$length / 6 digits" }
                for (row in listOf("123", "456", "789", "C0<")) {
                    content.addView(LinearLayout(activity).apply {
                        orientation = LinearLayout.HORIZONTAL
                        for (digit in row) addView(Button(activity).apply {
                            filterTouchesWhenObscured = true
                            text = when(digit) { 'C' -> "Clear"; '<' -> "Back"; else -> digit.toString() }
                            setOnClickListener {
                                when(digit) {
                                    'C' -> erase()
                                    '<' -> if(length > 0) { length--; buffer[length] = '\u0000' }
                                    else -> if(length < 6) buffer[length++] = digit
                                }
                                render()
                            }
                        }, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
                    })
                }
            }
            val dialog = AlertDialog.Builder(activity).setTitle(title)
                .setView(ScrollView(activity).apply { addView(content) })
                .setNegativeButton("Decline", null).setPositiveButton(positive, null).create()
            dialog.setOnDismissListener {
                erase()
                if (c.isActive) c.resume(null)
            }
            c.invokeOnCancellation { activity.runOnUiThread { erase(); dialog.dismiss() } }
            if (c.isActive) {
                dialog.window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
                dialog.show()
                dialog.window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
                dialog.getButton(AlertDialog.BUTTON_POSITIVE).filterTouchesWhenObscured = true
                dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                    val value = if (digits) String(buffer, 0, length) else "approved"
                    if (digits && (value.length != 6 || value.any { it !in '0'..'9' })) {
                        dialog.setTitle("Enter exactly six digits")
                    } else {
                        erase()
                        if (c.isActive) c.resume(value)
                        dialog.dismiss()
                    }
                }
            }
        }
    /** Discovery is not a trusted identity and cannot initiate key generation
     * without a local, foreground confirmation. */
    suspend fun confirmDiscoveredPairing(label:String):Boolean =
        ask("Pair a host", "Nearby pairing request: $label (unverified). Continue only if you have just run rba pair on your own computer.", positive="Continue") != null
    override suspend fun enterNumber(core: Cbor.Value.Map) = ask("Review authentication", V2OperatorText.authentication(core), true, "Submit number")
    override suspend fun enterPairingCode(): ByteArray? = ask("Pair with host", "Enter the six-digit code displayed by your host.", true, "Submit code")?.toByteArray(Charsets.US_ASCII)
    override suspend fun displayPairingCode(code: ByteArray): Boolean = ask("Pairing code", "Enter this code on your host: ${String(code, Charsets.US_ASCII)}\nDo not share it with anyone else.", positive = "Continue") != null
    override suspend fun reviewEnrollment(facts: V2Enrollment.Confirmation): ByteArray? =
        if (ask("Verify enrollment identity", V2OperatorText.enrollment(facts)) != null) facts.contextHash.copyOf() else null
    override suspend fun reviewCleanup(credentials: List<ByteArray>): Boolean = ask("Revoke old credentials", "The following locally disabled credentials will be removed from this same host:\n\n" + credentials.joinToString("\n") { V2OperatorText.hex(it) }) != null
    override suspend fun reviewInitialPolicy(offer: V2Message.Message, offerHash: ByteArray): ByteArray? =
        if (ask("Review initial permissions", V2OperatorText.policy(offer, offerHash)) != null) offerHash.copyOf() else null
    override suspend fun reviewPolicy(offer: V2Message.Message, digest: ByteArray): ByteArray? =
        if (ask("Review policy revision", V2OperatorText.policy(offer, digest)) != null) digest.copyOf() else null
}
