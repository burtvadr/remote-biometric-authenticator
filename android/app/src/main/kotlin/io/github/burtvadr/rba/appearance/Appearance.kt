package io.github.burtvadr.rba.appearance

/** How the app chooses light or dark colors. */
enum class ThemeMode(val label: String, val description: String) {
    SYSTEM("System", "Follow the device setting"),
    LIGHT("Light", "Always use the light theme"),
    DARK("Dark", "Always use the dark theme"),
}

/** The fingerprint mark used inside the app. */
enum class AppIconStyle(val label: String, val description: String) {
    AUTO("Automatic", "Follows the app's light or dark theme"),
    LIGHT("Light", "Light disc with a slate fingerprint"),
    DARK("Dark", "Dark disc with a light fingerprint"),
    MATERIAL("Material You", "Uses the current theme's container colors"),
    SCRCPY("Scrcpy", "Teal disc with a green fingerprint"),
}
