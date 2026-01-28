/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.zap.extension.graaljs;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import java.util.Map;
import javax.script.Compilable;
import javax.script.Invocable;
import javax.script.ScriptEngine;
import javax.script.ScriptException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Unit tests for {@link GraalJsEngineWrapper}. */
class GraalJsEngineWrapperUnitTest {

    private GraalJsEngineWrapper engineWrapper;

    @BeforeEach
    void setUp() {
        engineWrapper =
                new GraalJsEngineWrapper(
                        GraalJsEngineWrapperUnitTest.class.getClassLoader(), List.of(), null);
    }

    @Test
    void shouldReturnScriptEngineCleaner() {
        // Given / When
        ScriptEngine engine = engineWrapper.getEngine();

        // Then
        assertThat(engine, instanceOf(ScriptEngineCleaner.class));
    }

    @Test
    void shouldImplementCompilable() {
        // Given / When
        ScriptEngine engine = engineWrapper.getEngine();

        // Then
        assertThat(engine, instanceOf(Compilable.class));
    }

    @Test
    void shouldImplementInvocable() {
        // Given / When
        ScriptEngine engine = engineWrapper.getEngine();

        // Then
        assertThat(engine, instanceOf(Invocable.class));
    }

    @Test
    void shouldImplementAutoCloseable() {
        // Given / When
        ScriptEngine engine = engineWrapper.getEngine();

        // Then
        assertThat(engine, instanceOf(AutoCloseable.class));
    }

    @Test
    void shouldEvaluateSimpleScript() throws ScriptException {
        // Given
        ScriptEngine engine = engineWrapper.getEngine();

        // When
        Object result = engine.eval("1 + 1");

        // Then
        assertThat(result, instanceOf(Number.class));
    }

    @Test
    void shouldEvaluateScriptReturningObject() throws ScriptException {
        // Given
        ScriptEngine engine = engineWrapper.getEngine();

        // When
        Object result = engine.eval("({})");

        // Then
        assertThat(result, instanceOf(Map.class));
    }

    @Test
    void shouldThrowAfterClose() throws Exception {
        // Given
        ScriptEngine engine = engineWrapper.getEngine();
        engine.eval("const x = 1");

        // When
        ((AutoCloseable) engine).close();

        // Then
        assertThrows(IllegalStateException.class, () -> engine.eval("x + 1"));
    }
}
