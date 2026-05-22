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
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.scripts.automation.ScriptRunRecordAssembler.FailureContext;
import org.zaproxy.zap.extension.scripts.internal.db.ScriptRunRecorder;
import org.zaproxy.zap.extension.scripts.internal.db.ScriptRunRecorder.RunScript;
import org.zaproxy.zap.extension.scripts.zest.ZestScriptDiagnosticSource;
import org.zaproxy.zap.extension.scripts.zest.ZestScriptDiagnosticSource.ZestScriptPrintCapture;
import org.zaproxy.zap.extension.scripts.zest.ZestScriptDiagnosticSource.ZestScriptRunDiagnostic;

/** Unit tests for {@link ScriptRunRecordAssembler}. */
class ScriptRunRecordAssemblerUnitTest {

    private ExtensionScript extScript;
    private ScriptRunRecordAssembler assembler;

    @BeforeEach
    void setUp() {
        extScript = mock(ExtensionScript.class);
        assembler = new ScriptRunRecordAssembler(extScript);
    }

    @Test
    void shouldAssembleZestStandaloneSuccessFromPrintCapturesOnly() {
        // Given
        ScriptWrapper script =
                zestScript(
                        "zest-script",
                        new ZestScriptRunDiagnostic(
                                "",
                                "",
                                -1,
                                -1,
                                "",
                                null,
                                List.of(new ZestScriptPrintCapture(-1, "hello"))));
        ScriptJobOutputListener listener = new ScriptJobOutputListener(new AutomationProgress());
        listener.output(script, "ignored-zest-duplicate\n");

        // When
        List<RunScript> rows = assembler.assembleSingleScript(script, listener, Optional.empty());

        // Then
        assertThat(rows, hasSize(1));
        assertThat(rows.get(0).scriptName(), is("zest-script"));
        assertThat(rows.get(0).steps(), hasSize(1));
        assertThat(
                rows.get(0).steps().get(0).outputs().get(0).kind(),
                is(ScriptRunRecorder.OUTPUT_KIND_OUTPUT));
        assertThat(rows.get(0).steps().get(0).outputs().get(0).message(), is("hello"));
    }

    @Test
    void shouldAssembleNonZestStandaloneSuccessFromListenerOnly() {
        // Given
        ScriptWrapper script = mock(ScriptWrapper.class);
        when(script.getName()).thenReturn("js-script");
        when(script.getTypeName()).thenReturn("standalone");
        ScriptJobOutputListener listener = new ScriptJobOutputListener(new AutomationProgress());
        listener.output(script, "from-js\n");

        // When
        List<RunScript> rows = assembler.assembleSingleScript(script, listener, Optional.empty());

        // Then
        assertThat(rows, hasSize(1));
        assertThat(rows.get(0).steps(), hasSize(1));
        assertThat(rows.get(0).steps().get(0).outputs().get(0).message(), is("from-js"));
    }

    @Test
    void shouldAssembleZestStandaloneFailureWithErrorStep() {
        // Given
        ScriptWrapper script =
                zestScript(
                        "zest-script",
                        new ZestScriptRunDiagnostic(
                                "ctx",
                                "boom",
                                -1,
                                3,
                                "ZestClientClick",
                                null,
                                List.of(new ZestScriptPrintCapture(-1, "before"))));
        ScriptJobOutputListener listener = new ScriptJobOutputListener(new AutomationProgress());
        FailureContext failure = new FailureContext("boom", -1, 3, "ZestClientClick", null);

        // When
        List<RunScript> rows =
                assembler.assembleSingleScript(script, listener, Optional.of(failure));

        // Then
        assertThat(rows.get(0).steps(), hasSize(2));
        assertThat(
                rows.get(0).steps().get(0).outputs().get(0).kind(),
                is(ScriptRunRecorder.OUTPUT_KIND_OUTPUT));
        assertThat(rows.get(0).steps().get(1).sourceStepIndex(), is(3));
        assertThat(
                rows.get(0).steps().get(1).outputs().get(0).kind(),
                is(ScriptRunRecorder.OUTPUT_KIND_ERROR));
        assertThat(rows.get(0).steps().get(1).outputs().get(0).message(), is("boom"));
    }

    @Test
    void shouldAssembleChainSuccessWithPrintsPerMember() {
        // Given
        ScriptWrapper member1 = member("script1");
        ScriptWrapper member2 = member("script2");
        ScriptWrapper chain =
                zestScript(
                        "chain-script",
                        new ZestScriptRunDiagnostic(
                                "",
                                "",
                                -1,
                                -1,
                                "",
                                null,
                                List.of(new ZestScriptPrintCapture(2, "from script2"))));
        ScriptJobOutputListener listener = new ScriptJobOutputListener(new AutomationProgress());

        // When
        List<RunScript> rows =
                assembler.assembleChain(
                        chain, List.of(member1, member2), listener, Optional.empty());

        // Then
        assertThat(rows, hasSize(2));
        assertThat(rows.get(0).steps(), hasSize(0));
        assertThat(rows.get(1).steps(), hasSize(1));
        assertThat(rows.get(1).steps().get(0).outputs().get(0).message(), is("from script2"));
    }

    @Test
    void shouldAssembleAncillaryScriptOutputSeparately() {
        // Given
        ScriptWrapper script = mock(ScriptWrapper.class);
        when(script.getName()).thenReturn("standalone");
        when(script.getTypeName()).thenReturn("standalone");
        ScriptWrapper httpSender = mock(ScriptWrapper.class);
        when(httpSender.getName()).thenReturn("http-sender");
        when(httpSender.getTypeName()).thenReturn("httpsender");
        when(extScript.getScript("http-sender")).thenReturn(httpSender);

        ScriptJobOutputListener listener = new ScriptJobOutputListener(new AutomationProgress());
        listener.output(script, "main\n");
        listener.output(httpSender, "sender-line\n");

        // When
        List<RunScript> rows = assembler.assembleSingleScript(script, listener, Optional.empty());

        // Then
        assertThat(rows, hasSize(2));
        assertThat(rows.get(0).scriptName(), is("standalone"));
        assertThat(rows.get(1).scriptName(), is("http-sender"));
        assertThat(rows.get(1).steps().get(0).outputs().get(0).message(), is("sender-line"));
    }

    @Test
    void shouldNotRecordChainWrapperListenerOutputAsAncillaryScript() {
        // Given
        ScriptWrapper member1 = member("script1");
        ScriptWrapper member2 = member("script2");
        ScriptWrapper chain =
                zestScript(
                        "chain_script1",
                        new ZestScriptRunDiagnostic(
                                "",
                                "",
                                -1,
                                -1,
                                "",
                                null,
                                List.of(new ZestScriptPrintCapture(2, "from script2"))));
        ScriptJobOutputListener listener = new ScriptJobOutputListener(new AutomationProgress());
        listener.output(chain, "from script2\n");

        // When
        List<RunScript> rows =
                assembler.assembleChain(
                        chain, List.of(member1, member2), listener, Optional.empty());

        // Then
        assertThat(rows, hasSize(2));
        assertThat(rows.get(0).scriptName(), is("script1"));
        assertThat(rows.get(1).scriptName(), is("script2"));
        assertThat(rows.get(1).steps(), hasSize(1));
        assertThat(rows.get(1).steps().get(0).outputs().get(0).message(), is("from script2"));
    }

    @Test
    void shouldAssembleChainFailureWithListenerLinesOnMembers() {
        // Given
        ScriptWrapper member1 = member("script1");
        ScriptWrapper member2 = member("script2");
        ScriptWrapper chain =
                zestScript(
                        "chain-script",
                        new ZestScriptRunDiagnostic(
                                "ctx", "failed", 2, 4, "ZestClientClick", null, List.of()));
        ScriptJobOutputListener listener = new ScriptJobOutputListener(new AutomationProgress());
        listener.output(member2, "member-output\n");
        FailureContext failure = new FailureContext("failed", 2, 4, "ZestClientClick", null);

        // When
        List<RunScript> rows =
                assembler.assembleChain(
                        chain, List.of(member1, member2), listener, Optional.of(failure));

        // Then
        assertThat(rows.get(1).steps(), hasSize(2));
        assertThat(rows.get(1).steps().get(0).outputs().get(0).message(), is("member-output"));
        assertThat(
                rows.get(1).steps().get(1).outputs().get(0).kind(),
                is(ScriptRunRecorder.OUTPUT_KIND_ERROR));
    }

    private static ScriptWrapper member(String name) {
        ScriptWrapper wrapper = mock(ScriptWrapper.class);
        when(wrapper.getName()).thenReturn(name);
        when(wrapper.getTypeName()).thenReturn("standalone");
        return wrapper;
    }

    private static ScriptWrapper zestScript(String name, ZestScriptRunDiagnostic diagnostic) {
        return new ZestScriptWrapper(name, diagnostic);
    }

    private static final class ZestScriptWrapper extends ScriptWrapper
            implements ZestScriptDiagnosticSource {

        private final ZestScriptRunDiagnostic diagnostic;

        ZestScriptWrapper(String name, ZestScriptRunDiagnostic diagnostic) {
            setName(name);
            setType(new ScriptType(ExtensionScript.TYPE_STANDALONE, null, null, false));
            this.diagnostic = diagnostic;
        }

        @Override
        public Optional<ZestScriptRunDiagnostic> getLastRunDiagnostic() {
            return Optional.of(diagnostic);
        }
    }
}
