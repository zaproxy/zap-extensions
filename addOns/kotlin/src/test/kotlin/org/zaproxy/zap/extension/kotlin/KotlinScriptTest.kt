/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.zaproxy.zap.extension.kotlin

import org.junit.jupiter.api.BeforeAll
import org.zaproxy.zap.testutils.AbstractVerifyScriptTemplates
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import javax.script.Compilable

class KotlinScriptTest : AbstractVerifyScriptTemplates() {

    companion object {
        lateinit var se: Compilable
        @BeforeAll
        @JvmStatic
        fun setUp() {
            se = KotlinScriptEngineFactory(Thread.currentThread().contextClassLoader).scriptEngine as Compilable
        }
    }

    override fun getScriptExtension(): String? {
        return ".kts"
    }

    override fun parseTemplate(template: Path?) {
        val reader = Files.newBufferedReader(template, StandardCharsets.UTF_8)
        val s = se.compile(reader)
        s.eval()
    }
}