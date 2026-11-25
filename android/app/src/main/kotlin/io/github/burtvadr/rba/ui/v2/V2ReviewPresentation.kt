package io.github.burtvadr.rba.ui.v2

import android.os.Build
import android.os.Looper
import android.view.MotionEvent
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import io.github.burtvadr.rba.appearance.AppIconStyle
import io.github.burtvadr.rba.protocol.Cbor
import io.github.burtvadr.rba.protocol.V2Enrollment
import io.github.burtvadr.rba.protocol.V2Message
import io.github.burtvadr.rba.transport.V2ConnectionOwner
import io.github.burtvadr.rba.ui.OperatorFrame
import io.github.burtvadr.rba.ui.PairingCodeDisplay
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

/** One live, non-saveable review, rendered inside the original operator screen.
 * The V2 owner retains the deadline, exact transcript and authorization decision.
 * No independent dialog window, IME, clipboard or restored approval state. */
internal class V2ReviewPresentation(override val activity: FragmentActivity) : V2ConnectionOwner.Ui {
    private class Review(val title: String, val facts: String, val digits: Boolean,
                         val positive: String, val displayedCode: String?,
                         val continuation: CancellableContinuation<String?>) {
        val buffer = CharArray(6)
        var length by mutableStateOf(0)
        fun press(digit: Char) {
            when (digit) {
                'C' -> erase()
                '<' -> if (length > 0) { length--; buffer[length] = '\u0000' }
                in '0'..'9' -> if (length < buffer.size) buffer[length++] = digit
            }
        }
        fun erase() { buffer.fill('\u0000'); length = 0 }
    }
    private var pending by mutableStateOf<Review?>(null)
    val active: Boolean get() = pending != null

    private fun finish(review: Review, approved: Boolean) {
        check(Looper.myLooper() == Looper.getMainLooper())
        if (pending !== review) return // stale click cannot approve another request
        if (approved && review.digits && review.length != 6) return
        val value = if (!approved) null else if (review.digits) String(review.buffer, 0, review.length) else "approved"
        review.erase()
        pending = null
        if (review.continuation.isActive) review.continuation.resume(value)
    }
    fun reject() { pending?.let { finish(it, false) } }

    /** Both activities keep FLAG_SECURE. Reject the entire review on obscured
     * touches, including partially obscured windows, rather than permitting a
     * tap sequence to complete after the overlay disappears. */
    fun rejectObscured(event: MotionEvent): Boolean {
        if (!active) return false
        val flags = MotionEvent.FLAG_WINDOW_IS_OBSCURED or
            (if (Build.VERSION.SDK_INT >= 29) MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED else 0)
        if ((event.flags and flags) == 0) return false
        reject()
        return true
    }

    private suspend fun ask(title: String, facts: String, digits: Boolean = false,
                            positive: String = "Approve", displayedCode: String? = null): String? =
        suspendCancellableCoroutine { c ->
            check(Looper.myLooper() == Looper.getMainLooper())
            check(pending == null) { "Another review is active" }
            if (!c.isActive) return@suspendCancellableCoroutine
            val review = Review(title, facts, digits, positive, displayedCode, c)
            pending = review
            c.invokeOnCancellation {
                activity.runOnUiThread {
                    review.erase()
                    if (pending === review) pending = null
                }
            }
        }

    @Composable
    fun Content(iconStyle: AppIconStyle, modifier: Modifier = Modifier) {
        val review = pending ?: return
        key(review) {
            BackHandler { finish(review, false) }
            OperatorFrame(iconStyle, modifier) {
                Text(review.title, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.SemiBold)
                Text(review.facts, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                review.displayedCode?.let {
                    PairingCodeDisplay(it)
                }
                if (review.digits) {
                    Text("${review.length} / 6 digits", style = MaterialTheme.typography.titleMedium)
                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        for (row in listOf("123", "456", "789", "C0<")) {
                            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                for (digit in row) {
                                    OutlinedButton(onClick = { if (pending === review) review.press(digit) }, modifier = Modifier.weight(1f)) {
                                        Text(when (digit) { 'C' -> "Clear"; '<' -> "Back"; else -> digit.toString() })
                                    }
                                }
                            }
                        }
                    }
                }
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    Button(onClick = { finish(review, true) }, enabled = !review.digits || review.length == 6,
                           modifier = Modifier.weight(1f)) { Text(review.positive) }
                    OutlinedButton(onClick = { finish(review, false) }, modifier = Modifier.weight(1f)) { Text("Cancel") }
                }
            }
        }
    }

    suspend fun confirmDiscoveredPairing(label: String): Boolean =
        ask("Pair a host", "Nearby pairing request: $label (unverified). Continue only if you have just run rba pair on your own computer.", positive = "Continue") != null
    override suspend fun enterNumber(core: Cbor.Value.Map) = ask("Review authentication", V2OperatorText.authentication(core), true, "Submit number")
    override suspend fun enterPairingCode(): ByteArray? = ask("Confirm pairing", "Enter the six-digit code displayed by your host.", true, "Confirm")?.toByteArray(Charsets.US_ASCII)
    override suspend fun displayPairingCode(code: ByteArray): Boolean = ask("Pairing code", "Enter this code on your host. Do not share it with anyone else.", positive = "Continue", displayedCode = String(code, Charsets.US_ASCII)) != null
    override suspend fun reviewEnrollment(facts: V2Enrollment.Confirmation): ByteArray? =
        if (ask("Verify enrollment identity", V2OperatorText.enrollment(facts)) != null) facts.contextHash.copyOf() else null
    override suspend fun reviewCleanup(credentials: List<ByteArray>): Boolean = ask("Revoke old credentials", "The following locally disabled credentials will be removed from this same host:\n\n" + credentials.joinToString("\n") { V2OperatorText.hex(it) }) != null
    override suspend fun reviewInitialPolicy(offer: V2Message.Message, offerHash: ByteArray): ByteArray? =
        if (ask("Review initial permissions", V2OperatorText.policy(offer, offerHash)) != null) offerHash.copyOf() else null
    override suspend fun reviewPolicy(offer: V2Message.Message, digest: ByteArray): ByteArray? =
        if (ask("Review policy revision", V2OperatorText.policy(offer, digest)) != null) digest.copyOf() else null
}
