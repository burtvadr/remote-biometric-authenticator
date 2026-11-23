package io.github.burtvadr.rba.protocol

import java.io.File

/**
 * Standalone entry point for the conformance runner.
 *
 * Gradle is not available in every environment this project is developed in, so
 * the vector check can also be run directly:
 *
 * ```bash
 * kotlinc -jvm-target 21 -d out \
 *   src/main/kotlin/com/rba/protocol/Cbor.kt \
 *   src/main/kotlin/com/rba/protocol/Frame.kt \
 *   src/main/kotlin/com/rba/protocol/Messages.kt \
 *   src/test/kotlin/com/rba/protocol/VectorRunner.kt \
 *   src/test/kotlin/com/rba/protocol/Main.kt
 * java -cp "out:$HOME/kotlin/lib/kotlin-stdlib.jar" \
 *   io.github.burtvadr.rba.protocol.MainKt ../../protocol/test-vectors
 * ```
 *
 * Exit status is 0 only when every check passes, so this is usable from CI
 * without a test framework.
 */
fun main(args: Array<String>) {
    val dir = File(args.firstOrNull() ?: "protocol/test-vectors")
    if (!dir.isDirectory) {
        System.err.println("vector directory not found: ${dir.absolutePath}")
        System.err.println("usage: MainKt <path-to-protocol/test-vectors>")
        kotlin.system.exitProcess(2)
    }

    println("Running cross-language conformance vectors from ${dir.absolutePath}")
    val result = VectorRunner(dir).run()

    if (result.failures.isEmpty()) {
        println("PASS: ${result.checks} checks agreed with the Rust implementation")
        kotlin.system.exitProcess(0)
    } else {
        System.err.println("FAIL: ${result.failures.size} of ${result.checks} checks disagree")
        result.failures.forEach { System.err.println("  - $it") }
        kotlin.system.exitProcess(1)
    }
}