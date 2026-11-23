package io.github.burtvadr.rba.transport

import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothProfile
import android.content.Context
import android.os.Build
import android.util.Log
import io.github.burtvadr.rba.protocol.Frame
import java.io.IOException

/**
 * The Bluetooth Low Energy transport adapter.
 *
 * BLE is a carrier, not a security boundary. This adapter moves exactly the same
 * protocol frames the Wi-Fi transport moves, over GATT characteristics of at most
 * 20 bytes, and changes nothing about how a request is authenticated.
 *
 * The framing arithmetic lives in [BleFraming], which is Android-free so it can be
 * unit tested on the JVM.
 *
 * What it deliberately does not do:
 *
 * * Take identity from the BLE address, the advertised local name, or the service
 *   UUID. Those are routing data. Identity is the paired public key.
 * * Depend on link-layer encryption. `BOND` is requested because it is free
 *   confidentiality, but the proof does not rest on it.
 */
class BleTransport(private val context: Context) : AutoCloseable {

    private companion object {
        const val TAG = "BleTransport"
    }

    /**
     * Splits a frame into GATT-sized segments.
     *
     * Delegates to [BleFraming], which has no Android dependency so it can be
     * unit tested without a device.
     */
    fun segment(frame: Frame): List<ByteArray> = BleFraming.segment(frame)

    /** Events the transport surfaces to the session layer. */
    sealed interface Event {
        /** A whole frame arrived, reassembled from characteristic notifications. */
        data class FrameReceived(val frame: Frame) : Event

        /** The link is up and the service is discovered. */
        data object Connected : Event

        data class Disconnected(val reason: String) : Event
        data class Failed(val reason: String) : Event
    }

    /**
     * Splits an encoded frame into GATT-sized segments.
     *
     * Frame bytes are copied verbatim; the adapter never rewrites them. That is
     * what keeps the protocol byte-identical to the Wi-Fi transport.
     */
    private var gatt: BluetoothGatt? = null
    private val link = BleFraming.Link()
    private var onEvent: (Event) -> Unit = {}

    /**
     * The default Bluetooth adapter, or null when the device has none.
     *
     * Written as an explicit function because `x as? T ?.y ?: run { return }` does
     * not parse the way it reads.
     */
    private fun adapter(): android.bluetooth.BluetoothAdapter? {
        val manager = context.getSystemService(Context.BLUETOOTH_SERVICE)
            as? android.bluetooth.BluetoothManager
        return manager?.adapter
    }

    /** Opens a GATT connection and starts the read loop. */
    @Suppress("MissingPermission")
    fun connect(address: String, eventSink: (Event) -> Unit) {
        onEvent = eventSink
        val adapter = adapter()
        if (adapter == null) {
            eventSink(Event.Failed("no Bluetooth adapter"))
            return
        }
        if (!adapter.isEnabled) {
            eventSink(Event.Failed("Bluetooth is disabled"))
            return
        }

        val device = adapter.getRemoteDevice(address)
        val callback = object : BluetoothGattCallback() {
            @Suppress("MissingPermission")
            override fun onConnectionStateChange(g: BluetoothGatt?, status: Int, newState: Int) {
                when (newState) {
                    BluetoothProfile.STATE_CONNECTED -> {
                        g?.discoverServices()
                    }
                    BluetoothProfile.STATE_DISCONNECTED -> {
                        link.reset()
                        eventSink(Event.Disconnected("gatt status $status"))
                    }
                }
            }

            @Suppress("MissingPermission")
            override fun onServicesDiscovered(g: BluetoothGatt?, status: Int) {
                if (status != BluetoothGatt.GATT_SUCCESS) {
                    eventSink(Event.Failed("service discovery failed: $status"))
                    return
                }
                val service = g?.getService(BleFraming.SERVICE_UUID)
                if (service == null) {
                    // A device advertising the UUID but lacking the service is not
                    // our peer.
                    eventSink(Event.Failed("peer does not expose the expected service"))
                    return
                }
                val tx = service.getCharacteristic(BleFraming.TX_CHARACTERISTIC_UUID)
                val rx = service.getCharacteristic(BleFraming.RX_CHARACTERISTIC_UUID)
                if (tx == null || rx == null) {
                    eventSink(Event.Failed("peer is missing a required characteristic"))
                    return
                }
                // Ask for notifications on the device→host characteristic.
                g.setCharacteristicNotification(tx, true)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    g.setCharacteristicNotification(tx, true)
                }
                tx.getDescriptor(BleFraming.CLIENT_CHARACTERISTIC_CONFIG)?.let { descriptor ->
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        val status = g.writeDescriptor(
                            descriptor,
                            BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE,
                        )
                        if (status != BluetoothGatt.GATT_SUCCESS) {
                            eventSink(Event.Failed("cannot subscribe: $status"))
                        }
                    } else {
                        @Suppress("DEPRECATION")
                        descriptor.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                        @Suppress("DEPRECATION")
                        g.writeDescriptor(descriptor)
                    }
                }
                gatt = g
                eventSink(Event.Connected)
            }

            override fun onCharacteristicChanged(
                g: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic,
                value: ByteArray,
            ) {
                if (characteristic.uuid != BleFraming.TX_CHARACTERISTIC_UUID) return
                handleSegment(value)
            }

            @Deprecated("Required on API < 33; the platform still calls it there")
            @Suppress("DEPRECATION")
            override fun onCharacteristicChanged(
                g: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic,
            ) {
                if (characteristic.uuid != BleFraming.TX_CHARACTERISTIC_UUID) return
                handleSegment(characteristic.value ?: return)
            }
        }

        gatt = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            device.connectGatt(context, false, callback, android.bluetooth.BluetoothDevice.TRANSPORT_LE)
        } else {
            device.connectGatt(context, false, callback)
        }
    }

    private fun handleSegment(value: ByteArray) {
        link.push(value).fold(
            onSuccess = { frame -> if (frame != null) onEvent(Event.FrameReceived(frame)) },
            onFailure = { error -> onEvent(Event.Failed(error.message ?: "malformed frame")) },
        )
    }

    /** Writes a frame, segmented into characteristic-sized writes. */
    @Suppress("MissingPermission")
    fun send(frame: Frame) {
        val g = gatt ?: throw IOException("not connected")
        val service = g.getService(BleFraming.SERVICE_UUID) ?: throw IOException("no service")
        val rx = service.getCharacteristic(BleFraming.RX_CHARACTERISTIC_UUID)
            ?: throw IOException("no rx characteristic")
        for (segment in segment(frame)) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                val status = g.writeCharacteristic(
                    rx,
                    segment,
                    android.bluetooth.BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT,
                )
                if (status != BluetoothGatt.GATT_SUCCESS) {
                    Log.w(TAG, "characteristic write failed: $status")
                }
            } else {
                @Suppress("DEPRECATION")
                rx.value = segment
                @Suppress("DEPRECATION")
                g.writeCharacteristic(rx)
            }
        }
    }

    /** Discovers devices advertising our service. */
    @Suppress("MissingPermission")
    fun discover(timeoutMillis: Long, onFound: (List<String>) -> Unit) {
        val adapter = adapter()
        if (adapter == null) {
            onFound(emptyList())
            return
        }
        if (!adapter.isEnabled || !adapter.isDiscovering) {
            Log.i(TAG, "Bluetooth unavailable or not scanning; use the Wi-Fi transport")
            onFound(emptyList())
            return
        }
        // BLE scanning with a service UUID filter. The result is discovery data
        // only: it says "a candidate is nearby", never "this is my host".
        val found = mutableListOf<String>()
        val scanner = adapter.bluetoothLeScanner
        if (scanner == null) {
            onFound(emptyList())
            return
        }
        val settings = android.bluetooth.le.ScanSettings.Builder()
            .setScanMode(android.bluetooth.le.ScanSettings.SCAN_MODE_LOW_LATENCY)
            .build()
        val filter = android.bluetooth.le.ScanFilter.Builder()
            .setServiceUuid(android.os.ParcelUuid(BleFraming.SERVICE_UUID))
            .build()
        // The callback is retained because `stopScan` takes it as its argument.
        val callback = object : android.bluetooth.le.ScanCallback() {
            override fun onScanResult(
                callbackType: Int,
                result: android.bluetooth.le.ScanResult,
            ) {
                synchronized(found) { found.add(result.device.address) }
            }

            override fun onScanFailed(errorCode: Int) {
                Log.w(TAG, "BLE scan failed: $errorCode")
            }
        }
        try {
            scanner.startScan(listOf(filter), settings, callback)
        } catch (e: SecurityException) {
            // The runtime permission was refused; report no candidates rather than
            // failing silently.
            Log.w(TAG, "BLE scan not permitted: ${e.message}")
            onFound(emptyList())
            return
        }
        Thread {
            Thread.sleep(timeoutMillis)
            runCatching { scanner.stopScan(callback) }
            onFound(found.toList())
        }.apply { isDaemon = true }.start()
    }

    /**
     * Closes the link.
     *
     * `BLUETOOTH_CONNECT` is a runtime permission, so it may have been refused.
     * A failure to tidy up is not an authentication failure, so the exception is
     * swallowed deliberately rather than propagated into the session.
     */
    override fun close() {
        val g = gatt
        gatt = null
        link.reset()
        try {
            @Suppress("MissingPermission")
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                g?.disconnect()
            } else {
                @Suppress("DEPRECATION")
                g?.close()
            }
        } catch (e: SecurityException) {
            Log.w(TAG, "cannot close the GATT client: ${e.message}")
        }
    }
}