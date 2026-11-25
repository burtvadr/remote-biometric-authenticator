package io.github.burtvadr.rba.protocol

import io.github.burtvadr.rba.protocol.Cbor.Value
import java.io.InputStream
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.GeneralSecurityException
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECFieldFp
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec

/** Exact V2 schemas and transcripts; no session authorization or V1 fallback. */
object V2Message {
    enum class Kind(val code: Int) {
        HELLO(10),
        HELLOACK(11),
        AUTHREQUEST(12),
        NUMBERENTRY(13),
        MATCHED(14),
        AUTHRESPONSE(15),
        CANCEL(16),
        AUTHRESULT(17),
        REVOKE(18),
        REVOKERECEIPT(19),
        POLICYOFFER(20),
        POLICYDECISION(21),
        POLICYRECEIPT(22),
        ENROLLSTATUSRESULT(23),
        ENROLLSTATUS(24),
        ENROLLSTART(30),
        ENROLLSHARE(31),
        ENROLLCONFIRMA(32),
        ENROLLCONFIRMB(33),
        ENROLLEVIDENCE(34),
        ENROLLOFFER(35),
        ENROLLSTAGED(36),
        ENROLLRECEIPT(37),
        ENROLLCANCEL(38);
        companion object {
            fun fromCode(code: Int): Kind = entries.firstOrNull { it.code == code } ?: throw V2Wire.Invalid()
        }
    }
    enum class Domain(val label: String) {
        AUTHREQUEST("RBA-V2-AUTH-REQUEST"),
        MATCHED("RBA-V2-MATCHED"),
        AUTHRESPONSE("RBA-V2-AUTH-RESPONSE"),
        ENROLLKEYPROOF("RBA-V2-ENROLL-KEY-PROOF"),
        POLICY("RBA-V2-POLICY"),
        ATTEST("RBA-V2-ATTEST"),
        ENROLLOFFER("RBA-V2-ENROLL-OFFER"),
        ENROLLCONTEXT("RBA-V2-ENROLL-CONTEXT");
    }
    private enum class Schema(val fields: List<Pair<String,String>>) {
        SCOPE(listOf("purpose" to "ident", "service" to "ident", "operation" to "ident")),
        CONTEXT(listOf("source" to "ident", "detail" to "detail", "interaction_id" to "id")),
        GRANT(listOf("credential_id" to "id", "approver" to "id", "target" to "id", "scope" to "Scope")),
        AUTHCORE(listOf("v" to "version", "session_id" to "id", "request_id" to "id", "host_id" to "id", "credential_id" to "id", "host_nonce" to "b32", "device_nonce" to "b32", "channel" to "b32", "challenge" to "b32", "approver" to "id", "target" to "id", "approver_label" to "label", "target_label" to "label", "scope" to "Scope", "context" to "Context", "policy_revision" to "uint", "issued_at" to "uint", "expires_at" to "uint")),
        MATCHCORE(listOf("v" to "version", "session_id" to "id", "request_id" to "id", "channel" to "b32", "request_hash" to "b32", "matched" to "one")),
        RESPONSECORE(listOf("v" to "version", "session_id" to "id", "request_id" to "id", "channel" to "b32", "request_hash" to "b32", "match_hash" to "b32", "credential_id" to "id", "decision" to "one")),
        POLICYCORE(listOf("revision" to "uint", "grants" to "grants")),
        ATTESTCORE(listOf("v" to "version", "enrollment_id" to "id", "host_id" to "id", "nonce" to "b32", "channel" to "b32", "role" to "bit")),
        PROOFCORE(listOf("v" to "version", "enrollment_id" to "id", "host_id" to "id", "credential_id" to "id", "channel" to "b32", "nonce" to "b32", "transport_key" to "point", "biometric_key" to "point", "role" to "bit")),
        ENROLLCONTEXT(listOf("v" to "version", "enrollment_id" to "id", "host_id" to "id", "credential_id" to "id", "nonce" to "b32", "expires_at" to "uint", "direction" to "bit", "suite" to "suite", "channel" to "b32", "host_cert" to "b32", "provisional_client_cert" to "b32", "host_key" to "point", "provisional_client_key" to "point", "transport_key" to "point", "biometric_key" to "point")),
        HELLO(listOf("v" to "version", "host_id" to "id", "session_id" to "id", "host_nonce" to "b32", "capabilities" to "capabilities")),
        HELLOACK(listOf("v" to "version", "host_id" to "id", "session_id" to "id", "host_nonce" to "b32", "device_nonce" to "b32", "credential_id" to "id", "purpose" to "sessionPurpose", "capabilities" to "capabilities")),
        AUTHREQUEST(listOf("core" to "AuthCore", "signature" to "sig")),
        NUMBERENTRY(listOf("session_id" to "id", "request_id" to "id", "digits" to "digits")),
        MATCHED(listOf("core" to "MatchCore", "signature" to "sig")),
        AUTHRESPONSE(listOf("core" to "ResponseCore", "signature" to "sig")),
        CANCEL(listOf("session_id" to "id", "request_id" to "id")),
        AUTHRESULT(listOf("session_id" to "id", "request_id" to "id", "outcome" to "bit")),
        REVOKE(listOf("session_id" to "id", "credential_id" to "id", "token" to "b32")),
        REVOKERECEIPT(listOf("session_id" to "id", "credential_id" to "id")),
        POLICYOFFER(listOf("session_id" to "id", "revision" to "uint", "grants" to "grants", "digest" to "b32")),
        POLICYDECISION(listOf("session_id" to "id", "revision" to "uint", "digest" to "b32", "accepted" to "bit")),
        POLICYRECEIPT(listOf("session_id" to "id", "revision" to "uint", "digest" to "b32")),
        ENROLLSTATUSRESULT(listOf("session_id" to "id", "enrollment_id" to "id", "state" to "bit", "receipt" to "b32")),
        ENROLLSTATUS(listOf("session_id" to "id", "enrollment_id" to "id", "receipt" to "b32")),
        ENROLLSTART(listOf("v" to "version", "enrollment_id" to "id", "host_id" to "id", "nonce" to "b32", "expires_at" to "uint", "direction" to "bit", "suite" to "suite")),
        ENROLLSHARE(listOf("enrollment_id" to "id", "credential_id" to "id", "transport_key" to "point", "biometric_key" to "point", "share" to "point")),
        ENROLLCONFIRMA(listOf("enrollment_id" to "id", "share" to "point", "confirmation" to "b32")),
        ENROLLCONFIRMB(listOf("enrollment_id" to "id", "confirmation" to "b32")),
        ENROLLEVIDENCE(listOf("enrollment_id" to "id", "transport_chain" to "certs", "biometric_chain" to "certs", "transport_proof" to "sig", "biometric_proof" to "sig", "cleanup_tokens" to "tokens")),
        ENROLLOFFER(listOf("enrollment_id" to "id", "credential_id" to "id", "grants" to "grants", "revision" to "uint", "token" to "b32", "receipt" to "b32")),
        ENROLLSTAGED(listOf("enrollment_id" to "id", "offer_hash" to "b32")),
        ENROLLRECEIPT(listOf("enrollment_id" to "id", "receipt" to "b32", "offer_hash" to "b32")),
        ENROLLCANCEL(listOf("enrollment_id" to "id"));
    }
    private fun schema(kind: Kind): Schema = Schema.valueOf(kind.name)
    private fun schema(domain: Domain): Schema = when(domain) {
        Domain.AUTHREQUEST -> Schema.AUTHCORE
        Domain.MATCHED -> Schema.MATCHCORE
        Domain.AUTHRESPONSE -> Schema.RESPONSECORE
        Domain.ENROLLKEYPROOF -> Schema.PROOFCORE
        Domain.POLICY -> Schema.POLICYCORE
        Domain.ATTEST -> Schema.ATTESTCORE
        Domain.ENROLLOFFER -> Schema.ENROLLOFFER
        Domain.ENROLLCONTEXT -> Schema.ENROLLCONTEXT
    }
    private fun require(ok: Boolean) { if (!ok) throw V2Wire.Invalid() }
    private fun field(v: Value, name: String): Value = (v as? Value.Map)?.get(name) ?: throw V2Wire.Invalid()
    private fun bytes(v: Value) = (v as? Value.Bytes)?.value ?: throw V2Wire.Invalid()
    private fun text(v: Value) = (v as? Value.Text)?.value ?: throw V2Wire.Invalid()
    private fun uint(v: Value) = (v as? Value.Uint)?.value?.toULong() ?: throw V2Wire.Invalid()
    private fun array(v: Value) = (v as? Value.Arr)?.items ?: throw V2Wire.Invalid()
    private fun ident(s: String) = s.length in 1..64 && s.all { it in 'a'..'z' || it in '0'..'9' || it in "._-" }
    private fun label(s: String, max: Int) = V2TextProfile.label(s, max)
    private fun cmp(a: ByteArray,b: ByteArray): Int {
        for (i in 0 until minOf(a.size,b.size)) { val d = (a[i].toInt() and 255) - (b[i].toInt() and 255); if (d != 0) return d }
        return a.size.compareTo(b.size)
    }
    private val order = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",16)
    internal fun publicKey(raw: ByteArray): java.security.PublicKey {
        require(raw.size == 65 && raw[0] == 4.toByte())
        val x = BigInteger(1,raw.copyOfRange(1,33)); val y = BigInteger(1,raw.copyOfRange(33,65))
        return try {
            val params = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }.getParameterSpec(ECParameterSpec::class.java)
            // KeyFactory providers need not reject every invalid point at construction.
            // Public-coordinate membership check only; no secret-dependent EC arithmetic.
            val p = (params.curve.field as ECFieldFp).p
            require(x < p && y < p && y.multiply(y).mod(p) == x.multiply(x).multiply(x).add(params.curve.a.multiply(x)).add(params.curve.b).mod(p))
            KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x,y),params))
        } catch (_: GeneralSecurityException) { throw V2Wire.Invalid() }
    }
    private fun derSignature(raw: ByteArray): ByteArray {
        require(raw.size == 64)
        val r = BigInteger(1,raw.copyOfRange(0,32)); val s = BigInteger(1,raw.copyOfRange(32,64))
        require(r.signum() > 0 && r < order && s.signum() > 0 && s < order)
        val a = r.toByteArray(); val b = s.toByteArray()
        return byteArrayOf(0x30,(a.size+b.size+4).toByte(),0x02,a.size.toByte()) + a + byteArrayOf(0x02,b.size.toByte()) + b
    }
    private fun validateField(f: String, v: Value) {
        when(f) {
            "id" -> require(bytes(v).size == 16)
            "b32" -> require(bytes(v).size == 32)
            "version" -> require(uint(v) == V2Wire.VERSION.toULong())
            "uint" -> { uint(v) }
            "bit" -> require(uint(v) <= 1uL)
            "sessionPurpose" -> require(uint(v) <= 3uL)
            "one" -> require(uint(v) == 1uL)
            "ident" -> require(ident(text(v)))
            "label" -> require(label(text(v),128))
            "detail" -> require(label(text(v),256))
            "digits" -> require(text(v).length == 6 && text(v).all { it in '0'..'9' })
            "suite" -> require(text(v) == "rba-spake2-p256-sha256-v2")
            "point" -> { publicKey(bytes(v)) }
            "sig" -> { derSignature(bytes(v)) }
            "capabilities" -> {
                val a = array(v).map { text(it) }; require(a.all { ident(it) } && a.zipWithNext().all { (x,y) -> x < y })
                require(a.containsAll(listOf("number-match","attestation","tls-exporter","strong-biometric")))
            }
            "grants" -> {
                var previous: ByteArray? = null
                for (x in array(v)) { validate(Schema.GRANT,x); val enc = V2Wire.encodePayload(x); previous?.let { require(cmp(it,enc) < 0) }; previous = enc }
            }
            "certs" -> { val a = array(v); require(a.size in 1..8); require(a.all { bytes(it).size in 1..8192 }) }
            "tokens" -> require(array(v).all { bytes(it).size == 32 })
            else -> validate(Schema.valueOf(f.uppercase()),v)
        }
    }
    private fun validate(schema: Schema, v: Value) {
        require(v is Value.Map && v.entries.size == schema.fields.size)
        for ((name,f) in schema.fields) validateField(f,field(v,name))
        when(schema) {
            Schema.SCOPE -> {
                val p = text(field(v,"purpose")); val s = text(field(v,"service")); val o = text(field(v,"operation"))
                require(p == "authenticate" && (s to o) in setOf("rba" to "authenticate","sudo" to "service-auth","gdm" to "session-auth","polkit" to "action-auth"))
            }
            Schema.AUTHCORE -> { val i = uint(field(v,"issued_at")); val e = uint(field(v,"expires_at")); require(e > i && e-i in 1uL..60uL) }
            Schema.ENROLLSHARE,Schema.PROOFCORE,Schema.ENROLLCONTEXT -> {
                require(field(v,"transport_key") != field(v,"biometric_key"))
                if (schema == Schema.ENROLLCONTEXT) require(field(v,"provisional_client_key") != field(v,"transport_key") && field(v,"provisional_client_key") != field(v,"biometric_key"))
            }
            Schema.ENROLLSTATUSRESULT -> require((uint(field(v,"state")) == 0uL) == bytes(field(v,"receipt")).all { it == 0.toByte() })
            Schema.POLICYOFFER -> {
                val core = Cbor.ofMap("revision" to field(v,"revision"),"grants" to field(v,"grants"))
                require(bytes(field(v,"digest")).contentEquals(hash(Domain.POLICY,core)))
            }
            Schema.ENROLLOFFER -> {
                require(field(v,"token") != field(v,"receipt"))
                require(array(field(v,"grants")).all { field(it,"credential_id") == field(v,"credential_id") })
            }
            else -> Unit
        }
    }
    /** Stores canonical bytes, not caller-owned mutable arrays or lists. */
    class Message private constructor(val kind: Kind, private val canonical: ByteArray) {
        fun payload(): Value.Map = V2Wire.decodePayload(canonical)
        fun encode(): ByteArray = V2Wire.encodeFrame(kind.code,payload())
        companion object {
            fun create(kind: Kind,payload: Value): Message {
                val canonical = V2Wire.encodePayload(payload)
                validate(schema(kind),V2Wire.decodePayload(canonical))
                return Message(kind,canonical)
            }
            fun read(input: InputStream): Message {
                val (h,p) = V2Wire.readFrame(input)
                return create(Kind.fromCode(h.messageType),p)
            }
        }
    }
    fun transcript(domain: Domain, core: Value): ByteArray {
        val encoded = V2Wire.encodePayload(core); validate(schema(domain),V2Wire.decodePayload(encoded))
        return domain.label.toByteArray(Charsets.US_ASCII) + byteArrayOf(0) + encoded
    }
    fun hash(domain: Domain,core: Value): ByteArray = MessageDigest.getInstance("SHA-256").digest(transcript(domain,core))
    /** Verifies a supplied trusted key over the full transcript (no double hash). */
    fun verify(domain: Domain,core: Value,publicKey: ByteArray,signature: ByteArray) {
        require(domain in setOf(Domain.AUTHREQUEST,Domain.MATCHED,Domain.AUTHRESPONSE,Domain.ENROLLKEYPROOF))
        val msg = transcript(domain,core); val key = V2Message.publicKey(publicKey); val der = derSignature(signature)
        try {
            val verifier = Signature.getInstance("SHA256withECDSA"); verifier.initVerify(key); verifier.update(msg); require(verifier.verify(der))
        } catch (_: GeneralSecurityException) { throw V2Wire.Invalid() }
    }
}
