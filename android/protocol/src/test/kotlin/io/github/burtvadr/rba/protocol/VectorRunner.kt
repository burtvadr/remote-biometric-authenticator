package io.github.burtvadr.rba.protocol

import java.io.File
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec

/**
 * Runs the shared conformance vectors against the Kotlin implementation.
 *
 * This is the other half of the cross-language check: the Rust daemon has its own
 * runner over the same files. Both must agree byte-for-byte on canonical
 * encodings and on the signing transcript.
 *
 * ECDSA signatures are *not* compared byte-for-byte. The Android Keystore
 * chooses its own per-signature nonce, so signature bytes legitimately differ
 * between implementations; what must match is the message that was signed and
 * whether each sample verifies.
 */
class VectorRunner(private val vectorsDir: File) {

    class Failure(message: String) : AssertionError(message)

    private val failures = mutableListOf<String>()
    private var checks = 0

    fun run(): Result {
        canonicalCbor()
        nonCanonicalCbor()
        framing()
        messagePayloads()
        authRequestTranscript()
        signedFieldCoverage()
        signatures()
        pairingTranscript()

        return if (failures.isEmpty()) {
            Result(checks, failures)
        } else {
            Result(checks, failures)
        }
    }

    data class Result(val checks: Int, val failures: List<String>) {
        val passed: Boolean get() = failures.isEmpty()
    }

    private fun check(name: String, condition: Boolean, detail: String = "") {
        checks++
        if (!condition) failures += "$name${if (detail.isEmpty()) "" else ": $detail"}"
    }


    private fun loadJson(name: String): Map<String, Any?> {
        val file = File(vectorsDir, name)
        if (!file.exists()) {
            throw Failure("missing vector file ${file.absolutePath}; run: make vectors")
        }
        @Suppress("UNCHECKED_CAST")
        return MiniJson.parse(file.readText()) as Map<String, Any?>
    }

    // -----------------------------------------------------------------------

    private fun canonicalCbor() {
        val doc = loadJson("cbor-canonical.json")
        val cases = doc.objects("canonical")
        check("cbor-canonical.nonempty", cases.isNotEmpty(), "no canonical vectors")
        for (case in cases) {
            val name = case.text("name")
            val expected = Hex.decode(case.text("value_hex"))
            val decoded = try {
                Cbor.decode(expected)
            } catch (e: Exception) {
                failures += "$name: we rejected a canonical encoding: ${e.message}"
                continue
            }
            check("$name.decode", true)
            val reencoded = Cbor.encode(decoded)
            check(
                "$name.reencode",
                reencoded.contentEquals(expected),
                "re-encoding differs from the reference bytes",
            )
        }
    }

    private fun nonCanonicalCbor() {
        val doc = loadJson("cbor-canonical.json")
        val cases = doc.objects("non_canonical")
        check("cbor-noncanonical.nonempty", cases.isNotEmpty(), "no rejection vectors")
        for (case in cases) {
            val name = case.text("name")
            val rule = case.text("rule")
            val bytes = Hex.decode(case.text("value_hex"))
            val rejected = try {
                Cbor.decode(bytes)
                false
            } catch (e: Cbor.CborException) {
                true
            }
            check(
                "$name.rejected",
                rejected,
                "rule $rule: we accepted a non-canonical encoding",
            )
        }
    }

    private fun framing() {
        val doc = loadJson("framing.json")
        check("framing.header_len", doc.number("header_len") == 13L)
        for (case in doc.objects("frames")) {
            val name = case.text("name")
            val bytes = Hex.decode(case.text("frame_hex"))
            val decodedFrame = Frame.decode(bytes)
            if (decodedFrame == null) {
                failures += "$name: incomplete frame"
                continue
            }
            val (frame, consumed) = decodedFrame
            check("$name.length", consumed == bytes.size, "consumed $consumed of ${bytes.size}")
            check("$name.type", frame.msgType == case.number("msg_type").toInt())
            check(
                "$name.reencode",
                frame.encode().contentEquals(bytes),
                "frame encoding is not canonical",
            )
        }
        for (case in doc.objects("rejected")) {
            val bytes = Hex.decode(case.text("hex"))
            val rejected = try {
                Frame.decode(bytes) == null
                false
            } catch (e: Frame.FrameException) {
                true
            }
            check("${case.text("name")}.rejected", rejected, "accepted an invalid frame")
        }
    }

    private fun messagePayloads() {
        val doc = loadJson("messages.json")
        for (case in doc.objects("messages")) {
            val name = case.text("name")
            val payload = Hex.decode(case.text("payload_hex"))
            val type = case.number("msg_type").toInt()
            val frame = Frame(msgType = type, payload = payload)
            val encoded = frame.encode()
            val roundTripped = Frame.decode(encoded)
            if (roundTripped == null) {
                failures += "$name: frame did not round-trip"
                continue
            }
            val (decoded, _) = roundTripped
            check("$name.payload", decoded.payload.contentEquals(payload), "payload changed")
            check("$name.frame", decoded.encode().contentEquals(encoded), "frame not canonical")
        }

        // And the payloads must parse into the right message types.
        fun messageNamed(n: String): Pair<Frame, ByteArray>? {
            val c = doc.objects("messages").firstOrNull { it.text("name") == n }
                ?: run { failures += "missing vector $n"; return null }
            return Frame(msgType = c.number("msg_type").toInt(), payload = Hex.decode(c.text("payload_hex"))) to
                Hex.decode(c.text("payload_hex"))
        }
        messageNamed("session_hello_ack")?.let { (frame, _) ->
            val m = Message.fromFrame(frame)
            check("session_hello_ack.type", m is Message.SessionHelloAckMessage, "got ${m::class.simpleName}")
            check("session_hello_ack.key_id", (m as Message.SessionHelloAckMessage).v.deviceKeyId.length == 64)
        }
        messageNamed("auth_reject")?.let { (frame, _) ->
            val m = Message.fromFrame(frame) as Message.AuthRejectMessage
            check("auth_reject.reason", m.v.reason == 6, "expected USER_CANCELLED, got ${m.v.reason}")
        }
        messageNamed("error")?.let { (frame, _) ->
            val m = Message.fromFrame(frame) as Message.ErrorMessageEnvelope
            check("error.code", m.v.code == 10, "expected REPLAY, got ${m.v.code}")
        }
    }

    private fun authRequestTranscript() {
        val doc = loadJson("signing-transcript.json")
        check("transcript.domain", doc.text("domain_separator") == "RBA_AUTH_V1")
        val cases = doc.objects("cases")
        val baseline = cases.first { it.text("name") == "baseline" }
        val f = baseline.obj("fields")
        val request = AuthRequest(
            requestId = Id(Hex.decode(f.text("request_id"))),
            hostId = Id(Hex.decode(f.text("host_id"))),
            deviceId = Id(Hex.decode(f.text("device_id"))),
            username = f.text("username"),
            purpose = f.text("purpose"),
            service = f.text("service"),
            operation = f.text("operation"),
            challenge = Challenge(Hex.decode(f.text("challenge"))),
            issuedAt = f.number("issued_at"),
            expiresAt = f.number("expires_at"),
            sessionId = Id(Hex.decode(f.text("session_id"))),
        )
        check(
            "transcript.payload",
            Hex.encode(request.toPayload()) == baseline.text("payload_hex"),
            "payload encoding differs from the Rust implementation",
        )
        check(
            "transcript.signing_input",
            Hex.encode(request.signingInput()) == baseline.text("signing_input_hex"),
            "signing input differs from the Rust implementation",
        )
        check(
            "transcript.digest",
            Hex.encode(request.signingInputDigest()) == baseline.text("signing_input_sha256"),
            "signing input digest differs from the Rust implementation",
        )
        check("transcript.signed_fields", doc.texts("signed_fields").size == 10)
    }

    private fun signedFieldCoverage() {
        val doc = loadJson("signing-transcript.json")
        val cases = doc.objects("cases")
        val baseline = cases.first { it.text("name") == "baseline" }.text("signing_input_sha256")

        // These fields define the authorization scope: changing any of them must
        // change what the user signs.
        for (name in listOf(
            "different_username", "different_purpose", "different_service",
            "different_operation", "different_host", "different_device",
            "different_request_id", "different_challenge", "different_expiry",
        )) {
            val c = cases.firstOrNull { it.text("name") == name }
            if (c == null) {
                failures += "missing vector $name"
                continue
            }
            check(name, c.text("signing_input_sha256") != baseline, "signed field did not change the transcript")
        }

        // Display text is outside the signed scope by design.
        val display = cases.firstOrNull { it.text("name") == "with_unsigned_display_text" }
        if (display == null) {
            failures += "missing the display-text vector"
        } else {
            check(
                "with_unsigned_display_text",
                display.text("signing_input_sha256") == baseline,
                "unsigned display text must not change the signature",
            )
        }
    }

    private fun signatures() {
        val doc = loadJson("signatures.json")
        val device = doc.obj("device_key")
        val publicKey = decodePoint(Hex.decode(device.text("public_key_hex")))
        val publicKeyId = keyId(Hex.decode(device.text("public_key_hex")))
        check("sig.key_id", publicKeyId == device.text("key_id_hex"), "key id disagrees")
        check(
            "sig.short_fingerprint",
            publicKeyId.substring(0, 16) == device.text("short_fingerprint"),
            "short fingerprint disagrees",
        )

        val message = Hex.decode(doc.obj("message").text("signing_input_hex"))
        check(
            "sig.message_digest",
            Hex.encode(sha256(message)) == doc.obj("message").text("signing_input_sha256"),
        )

        for (case in doc.objects("verification_cases")) {
            val name = case.text("name")
            val sig = Hex.decode(case.text("signature_hex"))
            val expect = case.flag("expect_valid")
            if (expect == null) {
                failures += "$name: missing expect_valid"
                continue
            }
            val got = try {
                verifyEs256(publicKey, message, sig)
            } catch (e: Exception) {
                false
            }
            check("$name.validity", got == expect, "expected valid=$expect, got $got")
        }

        // The host key must not be able to impersonate the device.
        val hostKey = doc.obj("host_key")
        val hostPublic = decodePoint(Hex.decode(hostKey.text("public_key_hex")))
        val deviceScalar = Hex.decode(device.text("private_scalar_hex"))
        val forged = signEs256(deviceScalar, message)
        val verifiesAgainstHost = try {
            verifyEs256(hostPublic, message, forged)
        } catch (e: Exception) {
            false
        }
        check("sig.cross_key", !verifiesAgainstHost, "a signature verified against the wrong key")
    }

    private fun pairingTranscript() {
        val doc = loadJson("pairing.json")
        val session = doc.obj("session")
        val hostPub = Hex.decode(doc.obj("host_key").text("public_key_hex"))
        val devicePub = Hex.decode(doc.obj("device_key").text("public_key_hex"))
        val hostId = Id(Hex.decode(doc.text("host_id")))
        val deviceId = Id(Hex.decode(doc.text("device_id")))

        val hostEph = Hex.decode(doc.obj("host_ephemeral").text("public_key_hex"))
        val s = PairingSession.withDeviceEphemeralScalar(
            sessionId = Id(Hex.decode(session.text("session_id"))),
            hostNonce = Hex.decode(session.text("host_nonce")),
            hostEphPublicKey = hostEph,
            scalar = Hex.decode(doc.obj("device_ephemeral").text("private_scalar_hex")),
            publicKey = Hex.decode(doc.obj("device_ephemeral").text("public_key_hex")),
            codeEntry = CodeEntry.fromWire(doc.text("code_entry")),
        )
        s.derive(
            hostId = hostId,
            deviceId = deviceId,
            hostPub = hostPub,
            devicePub = devicePub,
            deviceNonce = Hex.decode(session.text("device_nonce")),
        )

        check("pairing.code", s.code() == doc.text("code"), "derived code differs from the Rust side")
        check(
            "pairing.device_mac",
            Hex.encode(s.deviceMac(hostId, deviceId, hostPub, devicePub)) == doc.text("device_mac_hex"),
            "device MAC differs",
        )
        check(
            "pairing.host_mac",
            Hex.encode(s.hostMac(hostId, deviceId, hostPub, devicePub)) == doc.text("host_mac_hex"),
            "host MAC differs",
        )
        // Device and host confirmations use different domain separators.
        check(
            "pairing.macs_differ",
            !constantTimeEquals(s.deviceMac(hostId, deviceId, hostPub, devicePub), s.hostMac(hostId, deviceId, hostPub, devicePub)),
        )

        for (case in doc.objects("must_differ")) {
            val mac = Hex.decode(case.text("mac_hex"))
            val accepted = s.deviceMac(hostId, deviceId, hostPub, devicePub)
            check(
                "${case.text("name")}.rejected",
                !constantTimeEquals(mac, accepted),
                "a substituted key produced the accepted MAC",
            )
        }
    }

    // -----------------------------------------------------------------------
    // P-256 helpers, used only by the vector runner.
    //
    // The app itself never handles key material: signing goes through Android
    // Keystore, which keeps the private key non-exportable and biometric-gated.
    // These helpers exist so the test harness can exercise the same vectors the
    // Rust side does.
    // -----------------------------------------------------------------------

    companion object {
        private val CURVE: ECParameterSpec =
            AlgorithmParameters.getInstance("EC")
                .apply { init(ECGenParameterSpec("secp256r1")) }
                .getParameterSpec(ECParameterSpec::class.java)

        private val ORDER: java.math.BigInteger = CURVE.order

        fun decodePoint(encoded: ByteArray): PublicKey {
            require(encoded.size == Limits.PUBKEY_LEN) { "public key must be 65 bytes" }
            require(encoded[0].toInt() == 0x04) { "expected an uncompressed point" }
            val x = java.math.BigInteger(1, encoded.copyOfRange(1, 33))
            val y = java.math.BigInteger(1, encoded.copyOfRange(33, 65))
            val point = ECPoint(x, y)
            check(isOnCurve(point)) { "point is not on P-256" }
            return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, CURVE))
        }

        /**
         * P-256 domain parameters, spelled out.
         *
         * The curve coefficients are hard-coded rather than read reflectively so
         * the check is explicit and cannot silently depend on a provider's
         * internal API shape.
         */
        private val FIELD_P: java.math.BigInteger = java.math.BigInteger(
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
            16,
        )
        private val CURVE_A: java.math.BigInteger = java.math.BigInteger.valueOf(-3)
        private val CURVE_B: java.math.BigInteger = java.math.BigInteger(
            "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
            16,
        )

        /** Checks that the decoded point satisfies `y^2 = x^3 - 3x + b (mod p)`. */
        private fun isOnCurve(point: ECPoint): Boolean {
            val x = point.affineX
            val y = point.affineY
            if (x.signum() < 0 || x >= FIELD_P || y.signum() < 0 || y >= FIELD_P) return false
            val lhs = y.modPow(java.math.BigInteger.TWO, FIELD_P)
            val rhs = x.modPow(java.math.BigInteger.TWO, FIELD_P).multiply(x)
                .add(CURVE_A.multiply(x))
                .add(CURVE_B)
                .mod(FIELD_P)
            return lhs == rhs
        }

        fun keyId(publicKeyBytes: ByteArray): String = Hex.encode(sha256(publicKeyBytes))

        private fun decodeScalarToPrivateKey(bytes: ByteArray): PrivateKey =
            KeyFactory.getInstance("EC")
                .generatePrivate(ECPrivateKeySpec(java.math.BigInteger(1, bytes), CURVE))

        /** Signs with a raw scalar, producing the protocol's fixed-width `r||s`. */
        fun signEs256(scalar: ByteArray, message: ByteArray): ByteArray {
            val key = decodeScalarToPrivateKey(scalar)
            val sig = Signature.getInstance("SHA256withECDSA")
            sig.initSign(key)
            sig.update(message)
            val der = sig.sign()
            return derToConcat(der, 32)
        }

        fun verifyEs256(publicKey: PublicKey, message: ByteArray, rawSignature: ByteArray): Boolean {
            require(rawSignature.size == Limits.SIG_LEN) { "signature must be 64 bytes" }
            val r = java.math.BigInteger(1, rawSignature.copyOfRange(0, 32))
            val s = java.math.BigInteger(1, rawSignature.copyOfRange(32, 64))
            // Reject r=0, s=0 and out-of-range components explicitly.
            if (r.signum() == 0 || s.signum() == 0) return false
            if (r >= ORDER || s >= ORDER) return false
            val sig = Signature.getInstance("SHA256withECDSA")
            sig.initVerify(publicKey)
            sig.update(message)
            return sig.verify(concatToDer(rawSignature))
        }

        /** Converts a DER `SEQUENCE { r, s }` into fixed-width `r || s`. */
        private fun derToConcat(der: ByteArray, size: Int): ByteArray {
            var i = 0
            require(der[i++] == 0x30.toByte()) { "bad DER sequence" }
            var len = (der[i++].toInt() and 0xFF)
            if (len > 0x80) {
                val n = len - 0x80
                i++ // long form length bytes are not used by ECDSA signatures here
                len = 0
                repeat(n) { len = (len shl 8) or (der[i++].toInt() and 0xFF) }
            }
            val out = ByteArray(size * 2)
            for (part in 0..1) {
                require(der[i++] == 0x02.toByte()) { "bad DER integer" }
                var l = (der[i++].toInt() and 0xFF)
                if (l > 0x80) {
                    val n = l - 0x80
                    l = 0
                    repeat(n) { l = (l shl 8) or (der[i++].toInt() and 0xFF) }
                }
                val value = der.copyOfRange(i, i + l)
                i += l
                // Left-pad to the fixed width.
                val padded = ByteArray(size)
                if (value.size <= size) {
                    value.copyInto(padded, size - value.size)
                } else {
                    // A leading zero byte may be present; drop it.
                    value.copyInto(padded, 0, value.size - size, value.size)
                }
                padded.copyInto(out, part * size)
            }
            return out
        }

        /** Builds a DER `SEQUENCE { r, s }` from fixed-width `r || s`. */
        private fun concatToDer(raw: ByteArray): ByteArray {
            fun encodeInt(part: ByteArray): ByteArray {
                var i = 0
                while (i < part.size - 1 && part[i].toInt() == 0) i++
                val trimmed = part.copyOfRange(i, part.size)
                val body = ByteArrayOutputStreamHelper()
                body.write(0x02)
                if (trimmed.size > 0x7F) {
                    body.write(0x81)
                    body.write(trimmed.size)
                } else {
                    body.write(trimmed.size)
                }
                body.write(trimmed)
                return body.toByteArray()
            }
            val r = encodeInt(raw.copyOfRange(0, 32))
            val s = encodeInt(raw.copyOfRange(32, 64))
            val body = ByteArrayOutputStreamHelper()
            body.write(r)
            body.write(s)
            val seq = body.toByteArray()
            val out = ByteArrayOutputStreamHelper()
            out.write(0x30)
            if (seq.size > 0x7F) {
                out.write(0x81)
                out.write(seq.size)
            } else {
                out.write(seq.size)
            }
            out.write(seq)
            return out.toByteArray()
        }
    }
}

/** Tiny helper so the DER code reads clearly. */
private class ByteArrayOutputStreamHelper {
    private val buffer = java.io.ByteArrayOutputStream()
    fun write(b: Int) = buffer.write(b)
    fun write(bytes: ByteArray) = buffer.write(bytes, 0, bytes.size)
    fun toByteArray(): ByteArray = buffer.toByteArray()
}

/**
 * A minimal JSON reader.
 *
 * The project deliberately has no JSON dependency in the protocol module: the
 * protocol itself uses canonical CBOR, and the only JSON here is reading the
 * test fixtures. Pulling in a general-purpose JSON library would add surface for
 * no benefit.
 */
object MiniJson {
    fun parse(text: String): Any? {
        val p = Parser(text)
        val v = p.value()
        p.skipWhitespace()
        require(p.atEnd()) { "trailing JSON content at ${p.pos}" }
        return v
    }

    private class Parser(private val s: String) {
        var pos = 0
        fun atEnd(): Boolean = pos >= s.length

        fun skipWhitespace() {
            while (pos < s.length && s[pos].isWhitespace()) pos++
        }

        fun value(): Any? {
            skipWhitespace()
            require(pos < s.length) { "unexpected end of JSON" }
            return when (val c = s[pos]) {
                '{' -> obj()
                '[' -> arr()
                '"' -> str()
                't' -> literal("true", true)
                'f' -> literal("false", false)
                'n' -> literal("null", null)
                else -> {
                    require(c == '-' || c.isDigit()) { "unexpected character '$c' at $pos" }
                    number()
                }
            }
        }

        private fun <T> literal(word: String, v: T): T {
            require(s.startsWith(word, pos)) { "invalid literal at $pos" }
            pos += word.length
            return v
        }

        private fun obj(): Map<String, Any?> {
            val out = LinkedHashMap<String, Any?>()
            pos++ // '{'
            skipWhitespace()
            if (pos < s.length && s[pos] == '}') { pos++; return out }
            while (true) {
                skipWhitespace()
                val k = str()
                skipWhitespace()
                require(s[pos] == ':') { "expected ':' at $pos" }
                pos++
                out[k] = value()
                skipWhitespace()
                require(pos < s.length) { "unterminated object" }
                when (s[pos]) {
                    ',' -> pos++
                    '}' -> { pos++; return out }
                    else -> throw AssertionError("expected ',' or '}' at $pos")
                }
            }
        }

        private fun arr(): List<Any?> {
            val out = ArrayList<Any?>()
            pos++ // '['
            skipWhitespace()
            if (pos < s.length && s[pos] == ']') { pos++; return out }
            while (true) {
                out += value()
                skipWhitespace()
                require(pos < s.length) { "unterminated array" }
                when (s[pos]) {
                    ',' -> pos++
                    ']' -> { pos++; return out }
                    else -> throw AssertionError("expected ',' or ']' at $pos")
                }
            }
        }

        private fun str(): String {
            require(s[pos] == '"') { "expected a string at $pos" }
            pos++
            val sb = StringBuilder()
            while (true) {
                require(pos < s.length) { "unterminated string" }
                when (val c = s[pos++]) {
                    '"' -> return sb.toString()
                    '\\' -> {
                        when (val e = s[pos++]) {
                            'n' -> sb.append('\n')
                            't' -> sb.append('\t')
                            'r' -> sb.append('\r')
                            'b' -> sb.append('\b')
                            'f' -> sb.append('')
                            '"' -> sb.append('"')
                            '\\' -> sb.append('\\')
                            '/' -> sb.append('/')
                            'u' -> {
                                val hex = s.substring(pos, pos + 4)
                                pos += 4
                                sb.append(hex.toInt(16).toChar())
                            }
                            else -> throw AssertionError("invalid escape \\$e")
                        }
                    }
                    else -> sb.append(c)
                }
            }
        }

        private fun number(): Any {
            val start = pos
            if (pos < s.length && s[pos] == '-') pos++
            while (pos < s.length && s[pos].isDigit()) pos++
            var isDouble = false
            if (pos < s.length && s[pos] == '.') {
                isDouble = true
                pos++
                while (pos < s.length && s[pos].isDigit()) pos++
            }
            val text = s.substring(start, pos)
            return if (isDouble) text.toDouble() else text.toLong()
        }
    }
}

// Small accessors so the runner reads cleanly. Named to avoid clashing with the
// standard library's `list`/`map` functions.
private fun Map<String, Any?>.objects(key: String): List<Map<String, Any?>> {
    @Suppress("UNCHECKED_CAST")
    return (this[key] as? List<Any?>)?.map {
        it as? Map<String, Any?> ?: throw AssertionError("field '$key' contains a non-object")
    } ?: emptyList()
}

private fun Map<String, Any?>.obj(key: String): Map<String, Any?> {
    @Suppress("UNCHECKED_CAST")
    return (this[key] as? Map<String, Any?>)
        ?: throw AssertionError("missing object field '$key'")
}

private fun Map<String, Any?>.text(key: String): String =
    this[key] as? String ?: throw AssertionError("missing string field '$key'")

private fun Map<String, Any?>.number(key: String): Long =
    (this[key] as? Number)?.toLong() ?: throw AssertionError("missing numeric field '$key'")

private fun Map<String, Any?>.texts(key: String): List<String> {
    @Suppress("UNCHECKED_CAST")
    return (this[key] as? List<Any?>)?.map {
        it as? String ?: throw AssertionError("field '$key' contains a non-string")
    } ?: emptyList()
}

private fun Map<String, Any?>.flag(key: String): Boolean? = this[key] as? Boolean