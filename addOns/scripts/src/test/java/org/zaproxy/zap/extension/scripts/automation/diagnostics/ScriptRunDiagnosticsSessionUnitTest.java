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
package org.zaproxy.zap.extension.scripts.automation.diagnostics;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.util.List;
import java.util.Optional;
import javax.jdo.PersistenceManager;
import javax.jdo.PersistenceManagerFactory;
import javax.jdo.Transaction;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptOutputListener;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.scripts.automation.diagnostics.ScriptRunDiagnosticsSession.RunContext;
import org.zaproxy.zap.extension.scripts.automation.diagnostics.ScriptRunRecordBuilder.ScriptMember;
import org.zaproxy.zap.extension.scripts.diagnostics.ScriptDiagnosticSource;
import org.zaproxy.zap.extension.scripts.diagnostics.ScriptDiagnosticSource.RunDiagnostics;
import org.zaproxy.zap.extension.scripts.diagnostics.ScriptDiagnosticSource.RunOutput;
import org.zaproxy.zap.extension.scripts.internal.db.ScriptRunRecorder;
import org.zaproxy.zap.extension.scripts.internal.db.ScriptsRun;
import org.zaproxy.zap.extension.scripts.internal.db.TableJdo;

/** Unit tests for {@link ScriptRunDiagnosticsSession}. */
class ScriptRunDiagnosticsSessionUnitTest {

    private static final RunContext CONTEXT =
            new RunContext(
                    "TestJob",
                    "Job: success",
                    "Job: failed",
                    List.of(new ScriptMember("my-script", "standalone")));

    @Test
    void shouldNotPersistSuccessWhenRunProducesNoSteps() {
        try (MockedStatic<TableJdo> tableJdo = mockStatic(TableJdo.class)) {
            ExtensionScript extensionScript = mock(ExtensionScript.class);
            ScriptRunDiagnosticsSession session = new ScriptRunDiagnosticsSession(extensionScript);
            ScriptWrapper script = new DiagnosticScriptWrapper("my-script", List.of());

            boolean result =
                    session.execute(script, new AutomationProgress(), () -> {}, CONTEXT, e -> {});

            assertThat(result, is(true));
            tableJdo.verify(TableJdo::getPmf, times(0));
        }
    }

    @Test
    void shouldPersistSuccessWhenScriptProducesStdout() {
        try (MockedStatic<TableJdo> tableJdo = mockStatic(TableJdo.class)) {
            PersistenceManagerFactory pmf = mock(PersistenceManagerFactory.class);
            PersistenceManager pm = mock(PersistenceManager.class);
            Transaction tx = mock(Transaction.class);
            tableJdo.when(TableJdo::getPmf).thenReturn(pmf);
            given(pmf.getPersistenceManager()).willReturn(pm);
            given(pm.currentTransaction()).willReturn(tx);
            given(tx.isActive()).willReturn(false);

            ExtensionScript extensionScript = mock(ExtensionScript.class);
            ScriptRunDiagnosticsSession session = new ScriptRunDiagnosticsSession(extensionScript);
            ScriptWrapper script =
                    new DiagnosticScriptWrapper(
                            "my-script",
                            List.of(
                                    new RunOutput(
                                            "my-script", 3, 0, "ZestActionPrint", "logged in")));

            boolean result =
                    session.execute(script, new AutomationProgress(), () -> {}, CONTEXT, e -> {});

            assertThat(result, is(true));
            @SuppressWarnings("rawtypes")
            ArgumentCaptor<Object> captor = ArgumentCaptor.forClass(Object.class);
            verify(pm, times(1)).makePersistent(captor.capture());
            ScriptsRun run =
                    captor.getAllValues().stream()
                            .filter(ScriptsRun.class::isInstance)
                            .map(ScriptsRun.class::cast)
                            .findFirst()
                            .orElseThrow();
            assertThat(run.getOutcome(), is(equalTo(ScriptRunRecorder.OUTCOME_SUCCESS)));
            assertThat(run.getScripts(), hasSize(1));
            assertThat(run.getScripts().get(0).getSteps(), hasSize(1));
            assertThat(
                    run.getScripts().get(0).getSteps().get(0).getOutputs().get(0).getMessage(),
                    is(equalTo("logged in")));
        }
    }

    @Test
    void shouldFlushProgressListenerBeforeReportingFailure() {
        ExtensionScript extensionScript = mock(ExtensionScript.class);
        ScriptRunDiagnosticsSession session = new ScriptRunDiagnosticsSession(extensionScript);
        ScriptWrapper script = new DiagnosticScriptWrapper("my-script", List.of());
        AutomationProgress progress = mock(AutomationProgress.class);
        ScriptOutputListener[] listenerHolder = new ScriptOutputListener[1];
        doAnswer(
                        inv -> {
                            listenerHolder[0] = inv.getArgument(0);
                            return null;
                        })
                .when(extensionScript)
                .addScriptOutputListener(any());

        boolean result =
                session.execute(
                        script,
                        progress,
                        () -> {
                            listenerHolder[0].output(script, "partial");
                            throw new RuntimeException("boom");
                        },
                        CONTEXT,
                        e -> {});

        assertThat(result, is(false));
        verify(progress).infoNoStdout("partial");
    }

    private static final class DiagnosticScriptWrapper extends ScriptWrapper
            implements ScriptDiagnosticSource {

        private final List<RunOutput> runOutputs;

        DiagnosticScriptWrapper(String name, List<RunOutput> runOutputs) {
            setName(name);
            setType(new ScriptType(ExtensionScript.TYPE_STANDALONE, null, null, false));
            this.runOutputs = runOutputs;
        }

        @Override
        public RunDiagnostics getRunDiagnostics() {
            return new RunDiagnostics(Optional.empty(), runOutputs);
        }

        /** No-op for test stub. */
        @Override
        public void clearRunDiagnostics() {}
    }
}
