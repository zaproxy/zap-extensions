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
package org.zaproxy.addon.kotlin;

import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import javax.script.Compilable;
import javax.script.CompiledScript;
import javax.script.ScriptEngine;
import org.junit.jupiter.api.BeforeAll;
import org.zaproxy.zap.testutils.AbstractVerifyScriptTemplates;

/** Verifies that the Kotlin script templates are parsed without errors. */
public class VerifyScriptTemplates extends AbstractVerifyScriptTemplates {

    private static ScriptEngine se;

    @BeforeAll
    public static void setUp() {
        se = new KotlinEngineWrapper(Thread.currentThread().getContextClassLoader()).getEngine();
    }

    @Override
    protected String getScriptExtension() {
        return ".kts";
    }

    @Override
    protected void parseTemplate(Path template) throws Exception {
        try (Reader reader = Files.newBufferedReader(template, StandardCharsets.UTF_8)) {
            Compilable c = (Compilable) se;
            CompiledScript cs = c.compile(reader);
            cs.eval();
        }
    }
}
