pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "rba"

// The protocol module is pure Kotlin with no Android dependencies, so its
// conformance vectors can be run without an emulator or an Android SDK. It is
// therefore included in the root build even though the app depends on it.
include(":protocol")
project(":protocol").projectDir = file("protocol")

// The app module needs the Android SDK, so it is only included when one is
// configured. That keeps `gradle :protocol:test` usable on a machine that only
// wants to verify protocol conformance.
if (System.getenv("ANDROID_HOME") != null || System.getenv("ANDROID_SDK_ROOT") != null) {
    include(":app")
} else {
    logger.lifecycle("ANDROID_HOME is not set; skipping the :app module")
}
