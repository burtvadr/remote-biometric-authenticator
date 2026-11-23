package io.github.burtvadr.rba.keystore

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.KeyPairGenerator

/**
 * The device's long-term authenticator key, held in Android Keystore.
 *
 * Properties that matter, and how each is obtained:
 *
 * | Property                | Mechanism |
 * |-------------------------|-----------|
 * | non-exportable          | the private key never enters the app process; only a `Signature` handle exists |
 * | requires user auth      | `setUserAuthenticationRequired(true)` |
 * | strong biometric only   | `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)` |
 * | invalidated on re-enrol | `setInvalidatedByBiometricEnrollment(true)` |
 * | hardware-backed         | detected, not assumed |
 *
 * The app cannot extract this key. It can only ask Keystore to sign, and Keystore
 * will refuse unless a strong biometric check immediately preceded the request.
 */
class DeviceAuthKey(
    private val keyStore: KeyStore = defaultKeyStore(),
    private val alias: String = DEFAULT_ALIAS,
) {

    enum class KeyLocation {
        /** Backed by a hardware keystore or TEE. */
        HARDWARE,

        /** Backed by StrongBox, a dedicated secure element. */
        STRONGBOX,

        /** Software-only. Still non-exportable, but weaker. */
        SOFTWARE,
    }

    data class Capabilities(
        val location: KeyLocation,
        val strongBiometricEnrolled: Boolean,
        val insideSecureHardware: Boolean,
    )

    /** Creates the key if absent. Idempotent, so it is safe to call on every launch. */
    fun ensureKey(): Boolean = try {
        if (!containsAlias()) generate()
        true
    } catch (e: Exception) {
        false
    }

    private fun containsAlias(): Boolean = keyStore.containsAlias(alias)

    /**
     * Generates an EC P-256 signing key.
     *
     * StrongBox is requested when the device advertises it, but its absence is not
     * fatal: rejecting such devices outright would exclude a lot of hardware for no
     * security gain in the threat model, since the model does not assume a
     * particular hardware security level.
     */
    private fun generate() {
        val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            // Auth required for every signature: there is no time window during
            // which the key can be used without a fresh biometric check.
            .setUserAuthenticationRequired(true)
            .apply {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    // API 30+: the authenticator class can be constrained directly.
                    setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                } else {
                    // API 28-29: a zero validity window is the strongest equivalent,
                    // and combined with setUserAuthenticationRequired it still forces
                    // an authentication per use. It cannot express the strong-class
                    // constraint, which is why hasStrongBiometric() is checked
                    // separately before this key is ever used.
                    @Suppress("DEPRECATION")
                    setUserAuthenticationValidityDurationSeconds(0)
                }
            }
            // A newly enrolled biometric invalidates the key. An attacker who
            // coerces the user into adding their own fingerprint must not thereby
            // gain a signing key bound to the old one.
            .setInvalidatedByBiometricEnrollment(true)
            // Signature only: the key must not be usable for encryption.
            .setDigests(KeyProperties.DIGEST_SHA256)

        if (hasStrongBox()) {
            try {
                builder.setIsStrongBoxBacked(true)
                generateWith(builder)
                return
            } catch (e: Exception) {
                // Fall back to the TEE or software keystore.
                builder.setIsStrongBoxBacked(false)
            }
        }
        generateWith(builder)
    }

    private fun generateWith(builder: KeyGenParameterSpec.Builder) {
        // EC key pairs come from KeyPairGenerator; KeyGenerator's generateKeyPair
        // exists only for some algorithms.
        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            ANDROID_KEYSTORE,
        )
        generator.initialize(builder.build())
        generator.generateKeyPair()
    }

    private fun hasStrongBox(): Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            packageManagerHasStrongBox()

    private fun packageManagerHasStrongBox(): Boolean =
        runCatching {
            val context = appContext ?: return false
            context.packageManager.hasSystemFeature(
                "android.hardware.strongbox_keystore",
            )
        }.getOrDefault(false)

    /**
     * Prepares a signature that the biometric prompt will authorise.
     *
     * The key is configured to require a fresh strong-biometric check for every
     * use, so a `Signature` must be created and initialised *before* the prompt and
     * handed to `BiometricPrompt` as a `CryptoObject`. Creating a new `Signature`
     * after the prompt returns does not work: Keystore has authorised that one
     * object, not the process, and the fresh one is rejected with
     * `UserNotAuthenticatedException`.
     *
     * Returns null when the key cannot be used at all (missing, invalidated by a
     * biometric re-enrolment, or otherwise unavailable). A null result MUST be
     * treated as a denial.
     */
    fun beginSigning(message: ByteArray): SigningOperation? = try {
        val privateKey = keyStore.getKey(alias, null) as? PrivateKey ?: return null
        val signature = Signature.getInstance(SIGNATURE_ALGORITHM).apply {
            initSign(privateKey)
        }
        SigningOperation(signature, message)
    } catch (e: android.security.keystore.KeyPermanentlyInvalidatedException) {
        // Biometrics changed. The key is now unusable and the device must be
        // re-paired with a new key.
        null
    } catch (e: Exception) {
        // Every other failure is also a denial.
        null
    }

    /**
     * A signature prepared for exactly one message and one biometric prompt.
     *
     * [sign] may be called once. Until the prompt succeeds, Keystore refuses to
     * produce a signature; after it succeeds, this is the object that carries the
     * authorisation.
     */
    class SigningOperation internal constructor(
        /** The object that `BiometricPrompt.CryptoObject` must wrap. */
        val signature: Signature,
        private val message: ByteArray,
    ) {
        private var used = false

        /** Completes the signature, or returns null if Keystore refuses. */
        fun sign(): ByteArray? = try {
            if (used) {
                null
            } else {
                used = true
                signature.update(message)
                derToRaw(signature.sign())
            }
        } catch (e: Exception) {
            null
        }
    }

    /** The public key, encoded as a raw uncompressed point (65 bytes). */
    fun publicKeyBytes(): ByteArray? = try {
        val cert = keyStore.getCertificate(alias)
        val encoded = cert.publicKey.encoded // X.509 SubjectPublicKeyInfo
        // Strip the SPKI wrapper to get the raw point the protocol specifies.
        extractRawPoint(encoded)
    } catch (e: Exception) {
        null
    }

    /**
     * Reports what this device actually provides.
     *
     * Recorded rather than assumed, because the threat model does not permit
     * treating every Android device as equally strong.
     */
    /** Null when the key does not exist yet or cannot be inspected. */
    fun capabilities(): Capabilities? {
        val location = try {
            val privateKey = keyStore.getKey(alias, null) as? PrivateKey ?: return null
            val factory = java.security.KeyFactory.getInstance(privateKey.algorithm)
            val keyInfo = factory.getKeySpec(privateKey, KeyInfo::class.java)
            // `securityLevel` exists from API 31; below that the deprecated
            // boolean is the only signal available.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                when (keyInfo.securityLevel) {
                    KeyProperties.SECURITY_LEVEL_STRONGBOX -> KeyLocation.STRONGBOX
                    KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> KeyLocation.HARDWARE
                    else -> KeyLocation.SOFTWARE
                }
            } else {
                @Suppress("DEPRECATION")
                if (keyInfo.isInsideSecureHardware) KeyLocation.HARDWARE else KeyLocation.SOFTWARE
            }
        } catch (e: Exception) {
            return null
        }
        return Capabilities(
            location = location,
            strongBiometricEnrolled = hasStrongBiometric(),
            insideSecureHardware = location != KeyLocation.SOFTWARE,
        )
    }

    /**
     * Whether a `BIOMETRIC_STRONG` sensor is enrolled and usable.
     *
     * A device with only a weak facial modality reports false. The app then
     * explains the limitation instead of silently downgrading, because accepting
     * a weaker biometric would weaken the security property the whole system rests
     * on.
     */
    fun hasStrongBiometric(): Boolean {
        val biometricManager = androidx.biometric.BiometricManager.from(appContext ?: return false)
        return biometricManager.canAuthenticate(
            androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG,
        ) == androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS
    }

    /** Deletes the key. The device then requires re-pairing. */
    fun delete() {
        if (containsAlias()) keyStore.deleteEntry(alias)
    }

    fun exists(): Boolean = containsAlias()

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
        private const val DEFAULT_ALIAS = "rba-device-key-v1"

        /**
         * Set once at startup so key generation can consult
         * `PackageManager.hasSystemFeature` without threading a context through
         * the crypto layer. The context is only ever used to read a system feature
         * flag; no key material is derived from it.
         */
        @Volatile
        private var appContext: android.content.Context? = null

        /** Called once from `Application.onCreate`. */
        fun initialize(context: android.content.Context) {
            appContext = context.applicationContext
        }

        fun defaultKeyStore(): KeyStore =
            KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

        /** Converts a DER `SEQUENCE { r, s }` into fixed-width `r || s`. */
        fun derToRaw(der: ByteArray): ByteArray {
            var i = 0
            require(der[i++] == 0x30.toByte()) { "bad DER sequence" }
            val len = readLength(der, i); i += lengthFieldSize(len)
            val out = ByteArray(64)
            for (part in 0..1) {
                require(der[i++] == 0x02.toByte()) { "bad DER integer" }
                val l = readLength(der, i); i += lengthFieldSize(l)
                val value = der.copyOfRange(i, i + l)
                i += l
                val padded = ByteArray(32)
                if (value.size <= 32) {
                    value.copyInto(padded, 32 - value.size)
                } else {
                    value.copyInto(padded, 0, value.size - 32, value.size)
                }
                padded.copyInto(out, part * 32)
            }
            return out
        }

        private fun readLength(der: ByteArray, at: Int): Int {
            val first = der[at].toInt() and 0xFF
            return if (first < 0x80) first else {
                val n = first - 0x80
                var v = 0
                for (k in 0 until n) v = (v shl 8) or (der[at + 1 + k].toInt() and 0xFF)
                v
            }
        }

        private fun lengthFieldSize(length: Int): Int =
            if ((length and 0xFF) < 0x80) 1 else 1 + byteCountOf(length)

        private fun byteCountOf(v: Int): Int {
            var n = 0
            var x = v
            while (x != 0) { n++; x = x shr 8 }
            return n
        }

        /**
         * Extracts the raw uncompressed EC point from an X.509
         * `SubjectPublicKeyInfo`.
         *
         * The DER structure is fixed for id-ecPublicKey with named curve P-256:
         * a 26-byte header followed by the point.
         */
        fun extractRawPoint(spki: ByteArray): ByteArray {
            require(spki.size == 91) { "unexpected SubjectPublicKeyInfo length ${spki.size}" }
            val point = spki.copyOfRange(spki.size - 65, spki.size)
            require(point[0] == 0x04.toByte()) { "expected an uncompressed point" }
            return point
        }
    }

}