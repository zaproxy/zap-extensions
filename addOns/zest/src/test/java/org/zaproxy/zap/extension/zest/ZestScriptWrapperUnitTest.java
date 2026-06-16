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
package org.zaproxy.zap.extension.zest;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.scripts.diagnostics.ScriptDiagnosticSource.RunFailureDiagnostic;
import org.zaproxy.zap.users.User;

/** Unit test for {@link ZestScriptWrapper}. */
class ZestScriptWrapperUnitTest {

    @BeforeEach
    void setup() {
        ExtensionZest extensionZest = mock(ExtensionZest.class);
        given(extensionZest.convertStringToElement(anyString())).willReturn(null);
        given(extensionZest.convertElementToString(any())).willReturn("{}");
        var extLoader = mock(ExtensionLoader.class);
        Control.initSingletonForTesting(mock(Model.class), extLoader);
        given(extLoader.getExtension(ExtensionZest.NAME)).willReturn(extensionZest);
    }

    private ScriptWrapper createMockScriptWrapper() {
        ScriptWrapper originalScript = mock(ScriptWrapper.class);
        ScriptType scriptType = mock(ScriptType.class);
        given(scriptType.getName()).willReturn(ExtensionScript.TYPE_STANDALONE);
        given(originalScript.getType()).willReturn(scriptType);
        return originalScript;
    }

    @Test
    void shouldGetAndSetUser() {
        // Given
        ZestScriptWrapper wrapper = new ZestScriptWrapper(createMockScriptWrapper());
        User user = mock(User.class);

        // When
        wrapper.setUser(user);

        // Then
        assertThat(wrapper.getUser(), is(sameInstance(user)));
    }

    @Test
    void shouldCloneWithUser() {
        // Given
        ZestScriptWrapper wrapper = new ZestScriptWrapper(createMockScriptWrapper());
        User user = mock(User.class);
        wrapper.setUser(user);

        // When
        ZestScriptWrapper clone = wrapper.clone();

        // Then
        assertThat(clone, is(not(sameInstance(wrapper))));
        assertThat(clone.getUser(), is(sameInstance(user)));
    }

    @Test
    void shouldCloneWithNullUser() {
        // Given
        ZestScriptWrapper wrapper = new ZestScriptWrapper(createMockScriptWrapper());
        // user remains null

        // When
        ZestScriptWrapper clone = wrapper.clone();

        // Then
        assertThat(clone, is(not(sameInstance(wrapper))));
        assertThat(clone.getUser(), is(nullValue()));
    }

    void shouldNotCopyLastRunFailureOntoClone() {
        ZestScriptWrapper wrapper = new ZestScriptWrapper(createMockScriptWrapper());
        wrapper.setLastRunFailure(
                new RunFailureDiagnostic(
                        "stale diagnostics from a prior run", "", -1, -1, "", null));

        ZestScriptWrapper clone = wrapper.clone();

        assertThat(clone.getRunDiagnostics().failure().isPresent(), is(false));
    }

    @Test
    void shouldReturnEmptyLastRunFailureWhenNoFailureRecorded() {
        ZestScriptWrapper wrapper = new ZestScriptWrapper(createMockScriptWrapper());

        assertThat(wrapper.getRunDiagnostics().failure().isPresent(), is(false));
    }

    @Test
    void shouldReturnLastRunFailureSnapshot() {
        ZestScriptWrapper wrapper = new ZestScriptWrapper(createMockScriptWrapper());
        wrapper.setLastRunFailure(
                new RunFailureDiagnostic(
                        "chain ctx", "ZestFoo - detail", 2, 13, "ZestClientFoo", "b64png"));

        Optional<RunFailureDiagnostic> diagnostic = wrapper.getRunDiagnostics().failure();

        assertThat(diagnostic.isPresent(), is(true));
        assertThat(diagnostic.get().context(), is(equalTo("chain ctx")));
        assertThat(diagnostic.get().detailMessage(), is(equalTo("ZestFoo - detail")));
        assertThat(diagnostic.get().chainScriptOrder(), is(equalTo(2)));
        assertThat(diagnostic.get().sourceStatementIndex(), is(equalTo(13)));
        assertThat(diagnostic.get().elementType(), is(equalTo("ZestClientFoo")));
        assertThat(diagnostic.get().screenshotBase64(), is(equalTo("b64png")));
    }

    @Test
    void shouldClearLastRunFailureAndRunOutputs() {
        ZestScriptWrapper wrapper = new ZestScriptWrapper(createMockScriptWrapper());
        wrapper.setLastRunFailure(new RunFailureDiagnostic("ctx", "detail", 1, 0, "ZestFoo", null));
        wrapper.appendRunOutput("script", 0, "ZestFoo", "line one");

        wrapper.clearRunDiagnostics();

        assertThat(wrapper.getRunDiagnostics().failure().isPresent(), is(false));
        assertThat(wrapper.getRunDiagnostics().outputs(), hasSize(0));
    }

    @Test
    void shouldAppendRunOutputsWithOrdinal() {
        ZestScriptWrapper wrapper = new ZestScriptWrapper(createMockScriptWrapper());
        wrapper.appendRunOutput("script-a", 1, "ZestActionPrint", "first");
        wrapper.appendRunOutput("script-a", 2, "ZestActionPrint", "second");

        assertThat(wrapper.getRunDiagnostics().outputs(), hasSize(2));
        assertThat(wrapper.getRunDiagnostics().outputs().get(0).ordinal(), is(equalTo(0)));
        assertThat(wrapper.getRunDiagnostics().outputs().get(0).message(), is(equalTo("first")));
        assertThat(wrapper.getRunDiagnostics().outputs().get(1).ordinal(), is(equalTo(1)));
    }
}
