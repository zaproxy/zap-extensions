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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.zaproxy.addon.kotlin.TestUtils.getScriptContents;

import java.io.StringWriter;
import java.io.Writer;
import javax.script.Compilable;
import javax.script.CompiledScript;
import javax.script.ScriptContext;
import javax.script.ScriptEngine;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class PrintOutputTests {

    private static ScriptEngine se;

    @BeforeAll
    public static void setUp() {
        se = new KotlinEngineWrapper(Thread.currentThread().getContextClassLoader()).getEngine();
    }

    @Test
    public void shouldPrintToScriptContextWriter() throws Exception {
        String script = getScriptContents("printTest.kts");

        ScriptContext sc = se.getContext();
        Writer originalWriter = sc.getWriter();

        try {
            StringWriter console = new StringWriter();
            sc.setWriter(console);
            Compilable c = (Compilable) se;
            CompiledScript cs = c.compile(script);

            cs.eval();

            sc.getWriter().flush();
            assertEquals("ZAP\nZAP", console.toString());
        } finally {
            sc.setWriter(originalWriter);
        }
    }
}
