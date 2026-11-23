package io.github.burtvadr.rba

import android.app.Application
import io.github.burtvadr.rba.keystore.DeviceAuthKey

/**
 * Application entry point.
 *
 * The only work done here is installing the application context so the keystore
 * layer can query a system feature flag. Everything else is driven from the
 * activity, and no credential or key material is touched during startup.
 */
class RbaApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        DeviceAuthKey.initialize(this)
    }
}