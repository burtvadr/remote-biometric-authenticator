package io.github.burtvadr.rba.ui.v2

import org.junit.Test
import java.io.File

class V2OperatorTextTest {
    @Test fun exactFieldsWithoutSecrets() {
        val vectors = generateSequence(File(System.getProperty("user.dir"))) { it.parentFile }
            .map { File(it, "protocol/test-vectors/v2-message.tsv") }.first { it.isFile }
        check(V2OperatorTextChecks.run(vectors) >= 20)
    }
}
