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
package org.zaproxy.zap.extension.scripts.automation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.zaproxy.zap.extension.script.ScriptWrapper;

/** Unit tests for {@link ScriptRunFailureDetail}. */
class ScriptRunFailureDetailUnitTest {

    @Test
    void shouldCompactExceptionToFirstLineOfMessage() {
        assertThat(
                ScriptRunFailureDetail.compactExceptionDetailForPersistence(
                        new RuntimeException("one\ntwo")),
                is(equalTo("one")));
    }

    @Test
    void shouldUseCauseMessageWhenRootMessageBlank() {
        Exception root = new RuntimeException();
        root.initCause(new IllegalStateException("cause line"));
        assertThat(
                ScriptRunFailureDetail.compactExceptionDetailForPersistence(root),
                is(equalTo("cause line")));
    }

    @Test
    void shouldPreferLastExceptionOverLongLastErrorDetails() {
        ScriptWrapper script = mock(ScriptWrapper.class);
        when(script.getLastException()).thenReturn(new RuntimeException("compact"));
        when(script.getLastErrorDetails())
                .thenReturn("first line of details\n" + "x".repeat(10_000));

        assertThat(
                ScriptRunFailureDetail.compactScriptOutputDetailForPersistence(script),
                is(equalTo("compact")));
    }

    @Test
    void shouldUseFirstLineOfLastErrorDetailsWhenNoException() {
        ScriptWrapper script = mock(ScriptWrapper.class);
        when(script.getLastException()).thenReturn(null);
        when(script.getLastErrorDetails()).thenReturn("summary only\n\tat foo(Bar.java:1)");

        assertThat(
                ScriptRunFailureDetail.compactScriptOutputDetailForPersistence(script),
                is(equalTo("summary only")));
    }

    @Test
    void shouldReturnEmptyForNullScript() {
        assertThat(ScriptRunFailureDetail.compactScriptOutputDetailForPersistence(null), is(""));
    }
}
