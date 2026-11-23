package io.github.burtvadr.rba.protocol

/**
 * Canonical CBOR, CTAP2 profile, restricted to the subset allowed by
 * `PROTOCOL.md` §8.5.
 *
 * This is an independent Kotlin implementation written from the specification. It
 * is checked against the Rust implementation through the shared vectors in
 * `protocol/test-vectors/cbor-canonical.json`.
 *
 * Two properties matter for security:
 *
 * 1. **Canonical-form enforcement on decode.** Non-canonical input is rejected,
 *    so exactly one byte string can represent a given logical message. That is
 *    what makes signing the encoding equivalent to signing the request.
 * 2. **Deterministic re-encoding.** `encode(decode(x)) == x` for every accepted
 *    `x`.
 *
 * Major types 0, 1, 2, 3, 4 and 5 are permitted, plus `false` and `true`. Tags,
 * floats, `undefined`, indefinite lengths and non-shortest integers are rejected.
 */
object Cbor {

    /** Maximum nesting depth; guards the recursive decoder against hostile input. */
    const val MAX_DEPTH = 16

    /** A CBOR value, limited to the permitted types. */
    sealed class Value {
        /**
         * Major type 0.
         *
         * CBOR integers are unsigned, but Kotlin's `Long` is signed, so values
         * above `Long.MAX_VALUE` cannot be held in `value` and are represented by
         * a negative number whose unsigned interpretation is correct. [asLong]
         * and [asBigInteger] do the conversion explicitly.
         */
        data class Uint(val value: Long) : Value() {
            /** Interprets the stored bits as an unsigned 64-bit value. */
            fun asBigInteger(): java.math.BigInteger =
                java.math.BigInteger(java.lang.Long.toUnsignedString(value))

            /** True when the value exceeds [Long.MAX_VALUE]. */
            val exceedsLong: Boolean get() = value < 0
        }
        /** Major type 1: represents `-1 - value`. */
        data class Nint(val value: Long) : Value()
        data class Bytes(val value: ByteArray) : Value() {
            override fun equals(other: Any?): Boolean =
                other is Bytes && value.contentEquals(other.value)

            override fun hashCode(): Int = value.contentHashCode()
        }

        data class Text(val value: String) : Value()
        data class Arr(val items: List<Value>) : Value()
        /**
         * Map entries in canonical order. Use [ofMap] rather than the
         * constructor so ordering cannot be got wrong.
         */
        data class Map(val entries: List<Pair<Value, Value>>) : Value() {
            /** Looks up a text key. */
            operator fun get(key: String): Value? =
                entries.firstOrNull { (k, _) -> k is Text && k.value == key }?.second

            /** True when the given text key is present. */
            fun has(key: String): Boolean = get(key) != null
        }

        data class Bool(val value: Boolean) : Value()
    }

    /** Convenience constructors that keep call sites readable. */
    fun uint(v: Long): Value = Value.Uint(v)
    fun uint(v: Int): Value = Value.Uint(v.toLong())
    fun bytes(b: ByteArray): Value = Value.Bytes(b)
    fun text(s: String): Value = Value.Text(s)
    fun bool(b: Boolean): Value = Value.Bool(b)
    fun array(items: List<Value>): Value = Value.Arr(items)
    fun arrayOf(vararg items: Value): Value = Value.Arr(items.toList())

    /**
     * Builds a map with text keys, sorted into canonical order.
     *
     * Canonical order is by *encoded key bytes*, not by string length or
     * lexicographic string order. Sorting here means a caller cannot
     * accidentally produce a non-canonical map.
     */
    fun ofMap(vararg pairs: Pair<String, Value>): Value.Map {
        val entries = pairs.map { (k, v) -> Value.Text(k) to v }.toMutableList()
        entries.sortWith { a, b -> compareEncoded(a.first, b.first) }
        return Value.Map(entries)
    }

    // -----------------------------------------------------------------------
    // Errors
    // -----------------------------------------------------------------------

    class CborException(message: String) : IllegalArgumentException(message)

    // -----------------------------------------------------------------------
    // Encoding
    // -----------------------------------------------------------------------

    fun encode(value: Value): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        encodeInto(value, out)
        return out.toByteArray()
    }

    /** Writes a major type and argument, choosing the shortest valid width. */
    private fun writeHead(out: java.io.ByteArrayOutputStream, major: Int, arg: Long) {
        val m = (major shl 5).toInt()
        // Comparisons are unsigned: a CBOR argument may exceed Long.MAX_VALUE.
        fun u(a: Long, b: Long): Int = java.lang.Long.compareUnsigned(a, b)
        when {
            u(arg, 24L) < 0 -> out.write(m or arg.toInt())
            u(arg, 0xFFL) <= 0 -> {
                out.write(m or 24); out.write(arg.toInt())
            }
            u(arg, 0xFFFFL) <= 0 -> {
                out.write(m or 25)
                out.write((arg ushr 8).toInt()); out.write(arg.toInt())
            }
            u(arg, 0xFFFFFFFFL) <= 0 -> {
                out.write(m or 26)
                for (shift in intArrayOf(24, 16, 8, 0)) out.write((arg ushr shift).toInt())
            }
            else -> {
                out.write(m or 27)
                for (shift in intArrayOf(56, 48, 40, 32, 24, 16, 8, 0)) {
                    out.write((arg ushr shift).toInt())
                }
            }
        }
    }

    private fun encodeInto(value: Value, out: java.io.ByteArrayOutputStream) {
        when (value) {
            is Value.Uint -> writeHead(out, 0, value.value)
            is Value.Nint -> writeHead(out, 1, value.value)
            is Value.Bytes -> {
                writeHead(out, 2, value.value.size.toLong())
                out.write(value.value)
            }
            is Value.Text -> {
                val bytes = value.value.toByteArray(Charsets.UTF_8)
                writeHead(out, 3, bytes.size.toLong())
                out.write(bytes)
            }
            is Value.Arr -> {
                writeHead(out, 4, value.items.size.toLong())
                value.items.forEach { encodeInto(it, out) }
            }
            is Value.Map -> {
                writeHead(out, 5, value.entries.size.toLong())
                value.entries.forEach { (k, v) ->
                    encodeInto(k, out)
                    encodeInto(v, out)
                }
            }
            is Value.Bool -> out.write(if (value.value) 0xF5 else 0xF4)
        }
    }

    /** Bytewise comparison of encoded values: shorter-is-smaller on a prefix. */
    private fun compareEncoded(a: Value, b: Value): Int {
        val ea = encode(a)
        val eb = encode(b)
        return ea.compareTo(eb)
    }

    /** Compares two byte arrays lexicographically. */
    private fun ByteArray.compareTo(other: ByteArray): Int {
        val n = minOf(size, other.size)
        for (i in 0 until n) {
            val d = (this[i].toInt() and 0xFF) - (other[i].toInt() and 0xFF)
            if (d != 0) return d
        }
        return size - other.size
    }

    // -----------------------------------------------------------------------
    // Strict decoding
    // -----------------------------------------------------------------------

    /**
     * Decodes exactly one canonical value, rejecting trailing bytes and every
     * non-canonical form described in §8.5.
     */
    fun decode(input: ByteArray): Value {
        val d = Decoder(input)
        val v = d.value(0)
        if (d.pos != input.size) throw CborException("trailing bytes after top-level item")
        return v
    }

    private class Decoder(private val input: ByteArray) {
        var pos = 0
            private set

        private fun byte(): Int {
            if (pos >= input.size) throw CborException("truncated input")
            return input[pos++].toInt() and 0xFF
        }

        private fun take(n: Int): ByteArray {
            if (n < 0 || pos + n > input.size) throw CborException("truncated input")
            val slice = input.copyOfRange(pos, pos + n)
            pos += n
            return slice
        }

        /** Reads the initial byte, returning `(major, additionalInformation)`. */
        private fun head(): Pair<Int, Int> {
            val b = byte()
            return (b shr 5) to (b and 0x1F)
        }

        /** Reads the argument, enforcing the shortest-form rule (R2). */
        private fun argument(ai: Int): Long {
            return when (ai) {
                in 0..23 -> ai.toLong()
                24 -> {
                    val v = byte().toLong()
                    if (v < 24) throw CborException("integer not in shortest form")
                    v
                }
                25 -> {
                    val v = ((byte().toLong() shl 8) or byte().toLong())
                    if (v <= 0xFF) throw CborException("integer not in shortest form")
                    v
                }
                26 -> {
                    var v = 0L
                    repeat(4) { v = (v shl 8) or byte().toLong() }
                    if (v <= 0xFFFF) throw CborException("integer not in shortest form")
                    v
                }
                27 -> {
                    // Accumulate in the bit pattern; `v` may legitimately be
                    // negative once the top bit is set, which is why the
                    // shortest-form test below uses an unsigned comparison.
                    var v = 0L
                    repeat(8) { v = (v shl 8) or byte().toLong() }
                    if (java.lang.Long.compareUnsigned(v, 0xFFFFFFFFL) <= 0) {
                        throw CborException("integer not in shortest form")
                    }
                    v
                }
                in 28..30 -> throw CborException("reserved additional information $ai")
                31 -> throw CborException("indefinite lengths are forbidden")
                else -> throw CborException("unreachable additional information $ai")
            }
        }

        fun value(depth: Int): Value {
            if (depth > MAX_DEPTH) throw CborException("nesting too deep")
            val (major, ai) = head()
            return when (major) {
                0 -> Value.Uint(argument(ai))
                1 -> Value.Nint(argument(ai))
                2 -> Value.Bytes(take(argument(ai).toInt()))
                3 -> {
                    val raw = take(argument(ai).toInt())
                    Value.Text(decodeUtf8(raw))
                }
                4 -> {
                    val n = argument(ai).toInt()
                    if (n > remainingItems(1)) throw CborException("truncated array")
                    Value.Arr((0 until n).map { value(depth + 1) })
                }
                5 -> {
                    val n = argument(ai).toInt()
                    if (n > remainingItems(2)) throw CborException("truncated map")
                    val entries = (0 until n).map { value(depth + 1) to value(depth + 1) }
                    for (i in 1 until n) {
                        if (compareEncoded(entries[i - 1].first, entries[i].first) >= 0) {
                            throw CborException("map keys unsorted or duplicated")
                        }
                    }
                    Value.Map(entries)
                }
                6 -> throw CborException("tags are forbidden")
                7 -> when (ai) {
                    20 -> Value.Bool(false)
                    21 -> Value.Bool(true)
                    31 -> throw CborException("indefinite lengths are forbidden")
                    else -> throw CborException("forbidden simple value $ai")
                }
                else -> throw CborException("unreachable major type $major")
            }
        }

        /**
         * Decodes text, rejecting anything that is not the shortest UTF-8 form.
         *
         * Java's decoder replaces malformed sequences instead of failing, so the
         * round-trip comparison is what actually enforces §8.6: an overlong
         * encoding, a surrogate or a value above U+10FFFF decodes to different
         * text and is rejected here.
         */
        private fun decodeUtf8(raw: ByteArray): String {
            // `CharsetDecoder.decode` throws on malformed input, but it reports
            // overlong forms, surrogates and out-of-range code points by
            // *replacing* them. So decoding is done by hand here to keep the
            // exception a `CborException` (which the caller expects to catch) and
            // then checked by round-tripping.
            val decoder = Charsets.UTF_8.newDecoder()
            decoder.onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
            decoder.onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
            val decoded = try {
                decoder.decode(java.nio.ByteBuffer.wrap(raw)).toString()
            } catch (e: java.nio.charset.CharacterCodingException) {
                throw CborException("text string is not valid UTF-8")
            }
            if (decoded.toByteArray(Charsets.UTF_8).contentEquals(raw)) return decoded
            throw CborException("text string is not canonical UTF-8")
        }

        /** Conservative upper bound on the number of further readable items. */
        private fun remainingItems(perEntry: Int): Int = (input.size - pos) / perEntry
    }
}