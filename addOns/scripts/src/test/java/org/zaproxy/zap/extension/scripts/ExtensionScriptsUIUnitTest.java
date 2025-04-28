/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.zap.extension.scripts;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import javax.script.ScriptException;
import org.junit.jupiter.api.Test;

public class ExtensionScriptsUIUnitTest {

    @Test
    void shouldExtractMsgFrom1ScriptException() {
        // Given
        ScriptException e = new ScriptException("test");
        // When
        String msg = ExtensionScriptsUI.extractScriptExceptionMessage(e);
        // Then
        assertThat(msg, is(equalTo("test")));
    }

    @Test
    void shouldExtractMsgFromDeeperScriptException() {
        // Given
        ScriptException se = new ScriptException("test");
        RuntimeException re = new RuntimeException("runtime", se);
        Exception e = new RuntimeException("exception", re);
        // When
        String msg = ExtensionScriptsUI.extractScriptExceptionMessage(e);
        // Then
        assertThat(msg, is(equalTo("test")));
    }

    @Test
    void shouldExtractMsgWithNoScriptException() {
        // Given
        RuntimeException re = new RuntimeException("runtime");
        Exception e = new RuntimeException("exception", re);
        // When
        String msg = ExtensionScriptsUI.extractScriptExceptionMessage(e);
        // Then
        assertThat(msg, is(equalTo("java.lang.RuntimeException: exception")));
    }
}
