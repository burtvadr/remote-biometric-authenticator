package io.github.burtvadr.rba.keystore

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.KeyStoreException
import android.util.Log
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import androidx.biometric.BiometricManager
import io.github.burtvadr.rba.protocol.V2Enrollment
import io.github.burtvadr.rba.session.V2DeviceStore
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.ProviderException
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/** Android-only V2 key adapter. No V1 aliases, import/export, or software
 * fallback. Local inspection is defense in depth, not remote attestation.
 * Call from the serialized V2 enrollment/credential owner, off the UI thread.
 */
internal object V2HardwareKeys {
    private const val PROVIDER = "AndroidKeyStore"
    private const val ATTESTATION = "1.3.6.1.4.1.11129.2.1.17"
    private const val SIGNATURE = "SHA256withECDSA"
    private const val MAX_TRANSCRIPT = 65536
    enum class Role { TRANSPORT, BIOMETRIC }
    enum class Location { TEE, STRONGBOX, HARDWARE } // pre-31 does not distinguish TEE and StrongBox
    /** Only safe metadata is logged: never aliases, challenges, certificates,
     * provider exception messages or stack traces containing key parameters. */
    class GenerationFailure internal constructor(val role: Role, val backend: String,
                                                 val stage: String, cause: Exception) :
        IllegalStateException("Attested hardware key $stage failed ($role, $backend)", cause)

    private fun generationFailure(role: Role, strongBox: Boolean, stage: String, cause: Exception): GenerationFailure {
        val backend = if (strongBox) "StrongBox" else "TEE"
        val details = if (Build.VERSION.SDK_INT >= 33) {
            val ks = generateSequence<Throwable>(cause) { it.cause }.take(8)
                .filterIsInstance<KeyStoreException>().firstOrNull()
            if (ks != null) " public_code=${ks.numericErrorCode} system_error=${ks.isSystemError} transient=${ks.isTransientFailure} retry=${ks.retryPolicy}"
            else ""
        } else ""
        Log.w("RbaV2Keys", "stage=$stage role=$role requested_backend=$backend exception=${cause.javaClass.simpleName}$details")
        return GenerationFailure(role, backend, stage, cause)
    }
    // Conscrypt delegates TLS 1.3 CertificateVerify for opaque EC keys as
    // prehashed ECDSA. Only the transport role may use that mechanism.
    private fun digests(role:Role)=if(role==Role.TRANSPORT)
        arrayOf(KeyProperties.DIGEST_NONE,KeyProperties.DIGEST_SHA256)
        else arrayOf(KeyProperties.DIGEST_SHA256)
    private fun store() = KeyStore.getInstance(PROVIDER).apply { load(null) }
    private fun alias(id: ByteArray, role: Role) = when (role) {
        Role.TRANSPORT -> V2DeviceStore.transportAlias(id)
        Role.BIOMETRIC -> V2DeviceStore.biometricAlias(id)
    }
    private fun strongAvailable(context: Context) = BiometricManager.from(context).canAuthenticate(
        BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS

    private class Loaded(val privateKey: PrivateKey, val point: ByteArray, val chain: List<ByteArray>, val location: Location)

    @Suppress("DEPRECATION")
    private fun inspect(ks: KeyStore, alias: String, role: Role, expected: ByteArray? = null, challenge: ByteArray? = null): Loaded {
        check(ks.isKeyEntry(alias)) { "V2 key missing; enrollment required" }
        val key = ks.getKey(alias, null) as? PrivateKey ?: error("V2 private key unavailable")
        check(key.algorithm == "EC" && key.encoded == null && key.format == null)
        val info = KeyFactory.getInstance(key.algorithm, PROVIDER).getKeySpec(key, KeyInfo::class.java)
        check(info.keystoreAlias == alias && info.origin == KeyProperties.ORIGIN_GENERATED && info.keySize == 256)
        check(info.purposes == KeyProperties.PURPOSE_SIGN && info.digests.toSet() == digests(role).toSet())
        val location = if (Build.VERSION.SDK_INT >= 31) when (info.securityLevel) {
            KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> Location.TEE
            KeyProperties.SECURITY_LEVEL_STRONGBOX -> Location.STRONGBOX
            else -> error("V2 hardware-backed key required")
        } else {
            check(info.isInsideSecureHardware) { "V2 hardware-backed key required" }
            Location.HARDWARE
        }
        if (role == Role.BIOMETRIC) {
            check(info.isUserAuthenticationRequired && info.isUserAuthenticationRequirementEnforcedBySecureHardware)
            check(info.userAuthenticationValidityDurationSeconds == -1)
            if (Build.VERSION.SDK_INT >= 30) check(info.userAuthenticationType == KeyProperties.AUTH_BIOMETRIC_STRONG)
            check(info.isInvalidatedByBiometricEnrollment)
            check(!info.isUserAuthenticationValidWhileOnBody)
        } else {
            check(!info.isUserAuthenticationRequired)
        }
        val certs = ks.getCertificateChain(alias) ?: error("V2 attestation chain missing")
        check(certs.size in 1..8)
        val leaf = certs.first() as? X509Certificate ?: error("V2 leaf is not X.509")
        val extension = leaf.getExtensionValue(ATTESTATION) ?: error("V2 attestation missing")
        val attestedChallenge = V2KeyEncoding.attestationChallenge(extension)
        if (challenge != null) check(attestedChallenge.contentEquals(challenge)) { "V2 attestation challenge mismatch" }
        val point = V2KeyEncoding.point(leaf.publicKey as? ECPublicKey ?: error("V2 key is not EC"))
        if (expected != null) check(point.contentEquals(expected)) { "V2 enrolled key mismatch" }
        val chain = certs.map { cert ->
            check(cert is X509Certificate)
            cert.encoded.also { check(it.size in 1..8192) }
        }
        return Loaded(key, point, chain, location)
    }

    // StrongBox is preferred, not required by the host's hardware policy.
    // Some implementations report a generic, permanent KeyMint failure instead
    // of StrongBoxUnavailableException. A separate TEE attempt is not a retry
    // of the failed StrongBox operation. Never relax the key specification.
    private fun canTryTee(failure: ProviderException): Boolean {
        if (failure is StrongBoxUnavailableException) return true
        if (Build.VERSION.SDK_INT < 33) return false
        val ks = generateSequence<Throwable>(failure) { it.cause }.take(8)
            .filterIsInstance<KeyStoreException>().firstOrNull() ?: return false
        return ks.numericErrorCode == KeyStoreException.ERROR_KEYMINT_FAILURE &&
            !ks.isTransientFailure && !ks.isSystemError
    }

    @Suppress("DEPRECATION")
    private fun generateOne(ks: KeyStore, name: String, role: Role, challenge: ByteArray, preferStrongBox: Boolean): Loaded {
        require(challenge.size == 32)
        check(!ks.containsAlias(name)) { "V2 key alias already exists" }
        fun generate(strongBox: Boolean) {
            val builder = KeyGenParameterSpec.Builder(name, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(*digests(role))
                .setAttestationChallenge(challenge.copyOf())
                .setIsStrongBoxBacked(strongBox)
                .setUserAuthenticationRequired(role == Role.BIOMETRIC)
            if (role == Role.BIOMETRIC) {
                if (Build.VERSION.SDK_INT >= 30) builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                else builder.setUserAuthenticationValidityDurationSeconds(-1)
                builder.setInvalidatedByBiometricEnrollment(true)
                builder.setUserAuthenticationValidWhileOnBody(false)
            }
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER).apply {
                initialize(builder.build())
            }.generateKeyPair()
        }
        var requestedStrongBox = preferStrongBox
        try {
            if (preferStrongBox) {
                try { generate(true) }
                catch (failure: ProviderException) {
                    // Do not overwrite even a partially generated key. An
                    // inspection/attestation failure never enters this branch.
                    if (!canTryTee(failure) || ks.containsAlias(name)) throw failure
                    generationFailure(role, true, "generation", failure)
                    Log.i("RbaV2Keys", "role=$role StrongBox generation failed; trying TEE once with unchanged attestation requirements")
                    requestedStrongBox = false
                    try { generate(false) }
                    catch (teeFailure: Exception) {
                        teeFailure.addSuppressed(failure)
                        throw teeFailure
                    }
                }
            } else generate(false)
        } catch (failure: Exception) {
            throw generationFailure(role, requestedStrongBox, "generation", failure)
        }
        try {
            return inspect(ks, name, role, challenge = challenge)
        } catch (failure: Exception) {
            throw generationFailure(role, requestedStrongBox, "inspection", failure)
        }
    }

    /** Key handles never leave this object. These public facts are copies. */
    class Credential internal constructor(id: ByteArray, transport: ByteArray, biometric: ByteArray,
                                          val transportLocation: Location, val biometricLocation: Location) {
        private val cid = id.copyOf(); private val tk = transport.copyOf(); private val bk = biometric.copyOf()
        fun id() = cid.copyOf()
        fun transportPoint() = tk.copyOf()
        fun biometricPoint() = bk.copyOf()
        fun transportChain() = inspect(store(), alias(cid, Role.TRANSPORT), Role.TRANSPORT, tk).chain
        fun biometricChain() = inspect(store(), alias(cid, Role.BIOMETRIC), Role.BIOMETRIC, bk).chain
        /** The TLS provider receives only an opaque transport-key handle and
         * its leaf certificate. The biometric key is never a TLS credential. */
        internal fun tlsKeyManager():javax.net.ssl.X509ExtendedKeyManager {
            val k=inspect(store(),alias(cid,Role.TRANSPORT),Role.TRANSPORT,tk)
            val leaf=java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(java.io.ByteArrayInputStream(k.chain.first())) as X509Certificate
            return io.github.burtvadr.rba.transport.V2TlsIdentity(k.privateKey,leaf)
        }
        /** Enrollment proof only. The state machine independently checks the exact signature. */
        fun transportProof(proofs: V2Enrollment.Proofs): ByteArray = signTransport(proofs.transport)
        private fun signTransport(message: ByteArray): ByteArray {
            require(message.size in 1..MAX_TRANSCRIPT)
            val input = message.copyOf()
            val key = inspect(store(), alias(cid, Role.TRANSPORT), Role.TRANSPORT, tk)
            return Signature.getInstance(SIGNATURE).run {
                initSign(key.privateKey); update(input); V2KeyEncoding.rawSignature(sign())
            }
        }
        /** Only the returned operation can use this prepared signature. It
         * must be bound to one strong biometric CryptoObject by V2BiometricPrompt. */
        fun prepareBiometric(context: Context, transcript: ByteArray): V2BiometricOperation {
            require(transcript.size in 1..MAX_TRANSCRIPT)
            check(strongAvailable(context)) { "Strong biometric unavailable" }
            val key = inspect(store(), alias(cid, Role.BIOMETRIC), Role.BIOMETRIC, bk)
            val signature = Signature.getInstance(SIGNATURE).apply { initSign(key.privateKey) }
            return V2BiometricOperation(signature, transcript)
        }
    }

    /** Fresh random identity and two fresh aliases. Never reuse a credential
     * ID, and never overwrite an existing alias. No local trust is activated. */
    @Synchronized fun generate(context: Context, challenges: V2Enrollment.Challenges): Credential {
        val tc = challenges.transport.copyOf(); val bc = challenges.biometric.copyOf()
        require(tc.size == 32 && bc.size == 32 && !tc.contentEquals(bc))
        require(tc.any { it != 0.toByte() } && bc.any { it != 0.toByte() })
        check(strongAvailable(context)) { "Strong biometric required for enrollment" }
        val ks = store()
        val id = ByteArray(16).apply { SecureRandom().nextBytes(this) }
        check(id.any { it != 0.toByte() })
        val ta = alias(id, Role.TRANSPORT); val ba = alias(id, Role.BIOMETRIC)
        check(!ks.containsAlias(ta) && !ks.containsAlias(ba))
        val strongBox = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        try {
            val t = generateOne(ks, ta, Role.TRANSPORT, tc, strongBox)
            val b = generateOne(ks, ba, Role.BIOMETRIC, bc, strongBox)
            check(!t.point.contentEquals(b.point))
            return Credential(id, t.point, b.point, t.location, b.location)
        } catch (failure: Exception) {
            // Both aliases were absent at entry, and only this serialized owner
            // creates them. Cleanup failures are not treated as success.
            for (name in listOf(ta, ba)) try { if (ks.containsAlias(name)) ks.deleteEntry(name) }
            catch (cleanup: Exception) { failure.addSuppressed(cleanup) }
            throw failure
        }
    }

    @Synchronized fun load(id: ByteArray, transport: ByteArray, biometric: ByteArray): Credential {
        require(!transport.contentEquals(biometric))
        val ks = store()
        val t = inspect(ks, alias(id, Role.TRANSPORT), Role.TRANSPORT, transport)
        val b = inspect(ks, alias(id, Role.BIOMETRIC), Role.BIOMETRIC, biometric)
        return Credential(id, t.point, b.point, t.location, b.location)
    }

    /** Revocation needs only the exact enrolled transport key, even when
     * the biometric key has been invalidated or deleted by Android. */
    @Synchronized fun revocationKeyManager(id:ByteArray,transport:ByteArray):javax.net.ssl.X509ExtendedKeyManager {
        val k=inspect(store(),alias(id,Role.TRANSPORT),Role.TRANSPORT,transport)
        val leaf=java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(java.io.ByteArrayInputStream(k.chain.first())) as X509Certificate
        return io.github.burtvadr.rba.transport.V2TlsIdentity(k.privateKey,leaf)
    }
    /** Exclusive canonical-store startup only. Snapshot all aliases before
     * deleting anything; do not touch unrelated or legacy aliases. */
    @Synchronized fun reclaimUnrecordedAliases(recordedIds:Set<String>){
        val ks=store();val names=ks.aliases().toList()
        for(name in V2AliasReclamation.unrecorded(names,recordedIds)){
            ks.deleteEntry(name);check(!ks.containsAlias(name))
        }
    }
    @Synchronized fun deleteUnrecorded(id:ByteArray,transport:ByteArray,biometric:ByteArray)=deleteInaccessible(id,transport,biometric)

    /** Caller MUST first make the credential inaccessible in the durable store
     * (or prove it was never recorded). Never delete another key on alias alone. */
    @Synchronized fun deleteInaccessible(id: ByteArray, transport: ByteArray, biometric: ByteArray) {
        val ks = store()
        val entries = listOf(alias(id, Role.TRANSPORT) to transport, alias(id, Role.BIOMETRIC) to biometric)
        // Check all extant keys before deleting either; invalidated keys can
        // still be identified via their public certificates.
        for ((name, expected) in entries) if (ks.containsAlias(name)) {
            val key = ks.getCertificate(name)?.publicKey as? ECPublicKey ?: error("V2 key identity unavailable")
            check(V2KeyEncoding.point(key).contentEquals(expected))
        }
        for ((name, _) in entries) if (ks.containsAlias(name)) { ks.deleteEntry(name);check(!ks.containsAlias(name)) }
    }
}
