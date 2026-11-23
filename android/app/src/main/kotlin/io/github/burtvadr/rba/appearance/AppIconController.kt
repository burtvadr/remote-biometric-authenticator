package io.github.burtvadr.rba.appearance

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import android.util.Log
import io.github.burtvadr.rba.MainActivity

/**
 * Switches the launcher entry between the icon variants.
 *
 * Android does not let an app change its application icon at runtime. The clean
 * way to offer selectable icons is to keep one activity alias per icon and enable
 * exactly one of them. The aliases all target [MainActivity]; the service and the
 * notification intents keep using the explicit activity, so only the launcher
 * entry changes.
 *
 * Launchers cache icons. A change can take a moment (or a launcher refresh) to
 * appear; the in-app badge changes immediately.
 */
object AppIconController {
    private const val TAG = "AppIconController"

    private val aliases = listOf("Auto", "Light", "Dark", "Material", "Scrcpy")

    fun apply(context: Context, style: AppIconStyle, dark: Boolean) {
        val target = when (style) {
            AppIconStyle.AUTO -> if (dark) "Dark" else "Light"
            AppIconStyle.LIGHT -> "Light"
            AppIconStyle.DARK -> "Dark"
            AppIconStyle.MATERIAL -> "Material"
            AppIconStyle.SCRCPY -> "Scrcpy"
        }

        val pm = context.packageManager
        val namespace = MainActivity::class.java.name.substringBeforeLast('.')

        // Enable the target first so the launcher never has a moment with no entry.
        setEnabled(pm, context, namespace, target, true)
        aliases.filter { it != target }.forEach { alias ->
            setEnabled(pm, context, namespace, alias, false)
        }
    }

    private fun setEnabled(
        pm: PackageManager,
        context: Context,
        namespace: String,
        alias: String,
        enabled: Boolean,
    ) {
        val component = ComponentName(context.packageName, "$namespace.Launcher$alias")
        runCatching {
            pm.setComponentEnabledSetting(
                component,
                if (enabled) {
                    PackageManager.COMPONENT_ENABLED_STATE_ENABLED
                } else {
                    PackageManager.COMPONENT_ENABLED_STATE_DISABLED
                },
                PackageManager.DONT_KILL_APP,
            )
        }.onFailure {
            Log.w(TAG, "could not switch launcher alias $alias", it)
        }
    }
}
