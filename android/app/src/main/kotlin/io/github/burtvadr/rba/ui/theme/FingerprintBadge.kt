package io.github.burtvadr.rba.ui.theme

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import io.github.burtvadr.rba.R
import io.github.burtvadr.rba.appearance.AppIconStyle

private const val GLYPH_RATIO = 0.75f

/**
 * The fingerprint mark shown on the overview and in the icon picker.
 *
 * This is deliberately an in-app mark, not a runtime replacement of the launcher
 * icon: Android owns launcher icons, and swapping activity aliases at runtime is
 * a good way to lose the shortcut. The adaptive launcher icon still supplies the
 * normal and monochrome layers.
 */
@Composable
fun FingerprintBadge(
    style: AppIconStyle,
    modifier: Modifier = Modifier,
    size: Dp = 84.dp,
) {
    val appIsDark = MaterialTheme.colorScheme.surface.luminance() < 0.5f
    val (container, glyph) = when (style) {
        AppIconStyle.AUTO -> if (appIsDark) {
            Color(0xFF2B2F36) to Color(0xFFD8DBE0)
        } else {
            Color(0xFFE8E9EC) to Color(0xFF51565F)
        }
        AppIconStyle.LIGHT -> Color(0xFFE8E9EC) to Color(0xFF51565F)
        AppIconStyle.DARK -> Color(0xFF2B2F36) to Color(0xFFD8DBE0)
        AppIconStyle.MATERIAL ->
            MaterialTheme.colorScheme.primaryContainer to
                MaterialTheme.colorScheme.onPrimaryContainer
        AppIconStyle.SCRCPY -> Color(0xFF077063) to Color(0xFF30DD81)
    }

    Box(
        modifier = modifier
            .size(size)
            .shadow(6.dp, CircleShape)
            .clip(CircleShape)
            .background(container),
        contentAlignment = Alignment.Center,
    ) {
        Icon(
            painter = painterResource(R.drawable.ic_fprint),
            contentDescription = null,
            tint = Color.Black.copy(alpha = if (appIsDark) 0.45f else 0.22f),
            modifier = Modifier
                .size(size * GLYPH_RATIO)
                .offset(y = 1.5.dp),
        )
        Icon(
            painter = painterResource(R.drawable.ic_fprint),
            contentDescription = "Fingerprint",
            tint = glyph,
            modifier = Modifier.size(size * GLYPH_RATIO),
        )
    }
}
