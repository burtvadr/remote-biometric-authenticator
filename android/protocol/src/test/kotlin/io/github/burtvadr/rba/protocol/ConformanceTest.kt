package io.github.burtvadr.rba.protocol

import java.io.File
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Cross-language conformance.
 *
 * These assertions are deliberately coarse: the interesting detail is in
 * [VectorRunner], which checks each vector individually so a failure names the
 * exact case. This test exists so a drift in the *set* of vectors, or a missing
 * fixture directory, fails loudly and early.
 */
class ConformanceTest {

    private fun vectorsDir(): File {
        val candidates = listOf(
            File("../protocol/test-vectors"),
            File("protocol/test-vectors"),
            File("../../protocol/test-vectors"),
            File(System.getProperty("rba.vectors.dir") ?: "protocol/test-vectors"),
        )
        return candidates.firstOrNull { it.isDirectory }
            ?: error(
                "cannot locate protocol/test-vectors; run the tests from the repository " +
                    "root, or pass -Drba.vectors.dir=/path/to/test-vectors"
            )
    }

    @Test
    fun `the Kotlin implementation agrees with the Rust implementation on every vector`() {
        val result = VectorRunner(vectorsDir()).run()
        if (result.failures.isNotEmpty()) {
            val detail = result.failures.joinToString("\n  - ")
            error(
                "${result.failures.size} of ${result.checks} conformance checks failed:\n  - $detail"
            )
        }
        assertTrue(result.checks > 100, "expected a substantial number of checks, ran ${result.checks}")
    }

    @Test
    fun `every required vector file is present and non-empty`() {
        val dir = vectorsDir()
        for (name in listOf(
            "cbor-canonical.json",
            "framing.json",
            "messages.json",
            "signing-transcript.json",
            "signatures.json",
            "pairing.json",
        )) {
            val f = File(dir, name)
            assertTrue(f.isFile, "missing vector file $name")
            assertTrue(f.length() > 0, "empty vector file $name")
        }
    }
}