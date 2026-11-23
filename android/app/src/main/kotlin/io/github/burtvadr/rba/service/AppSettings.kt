package io.github.burtvadr.rba.service

import android.content.Context
import io.github.burtvadr.rba.appearance.AppIconStyle
import io.github.burtvadr.rba.appearance.ThemeMode

/** Small preferences that survive a process restart. */
object AppSettings {
    private const val PREFS = "rba-settings"
    private const val KEY_BACKGROUND_ENABLED = "background_enabled"
    private const val KEY_NOTIFICATION_ASKED = "notification_asked"
    private const val KEY_THEME_MODE = "theme_mode"
    private const val KEY_ICON_STYLE = "icon_style"
    private const val KEY_DYNAMIC_COLOR = "dynamic_color"

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** Whether the user's last choice was to keep operating in the background. */
    fun backgroundEnabled(context: Context): Boolean =
        prefs(context).getBoolean(KEY_BACKGROUND_ENABLED, false)

    fun setBackgroundEnabled(context: Context, enabled: Boolean) {
        prefs(context).edit().putBoolean(KEY_BACKGROUND_ENABLED, enabled).apply()
    }

    fun notificationAsked(context: Context): Boolean =
        prefs(context).getBoolean(KEY_NOTIFICATION_ASKED, false)

    fun setNotificationAsked(context: Context, asked: Boolean) {
        prefs(context).edit().putBoolean(KEY_NOTIFICATION_ASKED, asked).apply()
    }

    fun themeMode(context: Context): ThemeMode {
        val stored = prefs(context).getString(KEY_THEME_MODE, null)
        return runCatching { ThemeMode.valueOf(stored.orEmpty()) }
            .getOrDefault(ThemeMode.SYSTEM)
    }

    fun setThemeMode(context: Context, mode: ThemeMode) {
        prefs(context).edit().putString(KEY_THEME_MODE, mode.name).apply()
    }

    fun iconStyle(context: Context): AppIconStyle {
        val stored = prefs(context).getString(KEY_ICON_STYLE, null)
        return runCatching { AppIconStyle.valueOf(stored.orEmpty()) }
            .getOrDefault(AppIconStyle.AUTO)
    }

    fun setIconStyle(context: Context, style: AppIconStyle) {
        prefs(context).edit().putString(KEY_ICON_STYLE, style.name).apply()
    }

    /** Material You wallpaper colors; off by default so the designed scheme appears. */
    fun dynamicColor(context: Context): Boolean =
        prefs(context).getBoolean(KEY_DYNAMIC_COLOR, false)

    fun setDynamicColor(context: Context, enabled: Boolean) {
        prefs(context).edit().putBoolean(KEY_DYNAMIC_COLOR, enabled).apply()
    }
}
