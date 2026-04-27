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
package org.zaproxy.zap.extension.scripts.internal.db;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.util.List;
import javax.jdo.PersistenceManager;
import javax.jdo.PersistenceManagerFactory;
import javax.jdo.Transaction;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;

/** Unit tests for {@link ScriptRunRecorder}. */
class ScriptRunRecorderUnitTest {

    @Test
    void shouldPersistFailedRunWithScriptMetadataAndMessages() {
        try (MockedStatic<TableJdo> tableJdo = mockStatic(TableJdo.class)) {
            PersistenceManagerFactory pmf = mock(PersistenceManagerFactory.class);
            PersistenceManager pm = mock(PersistenceManager.class);
            Transaction tx = mock(Transaction.class);
            tableJdo.when(TableJdo::getPmf).thenReturn(pmf);
            given(pmf.getPersistenceManager()).willReturn(pm);
            given(pm.currentTransaction()).willReturn(tx);
            given(tx.isActive()).willReturn(false);

            ScriptRunRecorder.recordSingleScriptFailure(
                    "my-script", "standalone", "script blew up", "raw error");

            @SuppressWarnings("rawtypes")
            ArgumentCaptor<Object> captor = ArgumentCaptor.forClass(Object.class);
            verify(pm, times(1)).makePersistent(captor.capture());
            ScriptsRun run =
                    captor.getAllValues().stream()
                            .filter(ScriptsRun.class::isInstance)
                            .map(ScriptsRun.class::cast)
                            .findFirst()
                            .orElseThrow();
            assertThat(run.getSummary(), is(equalTo("script blew up")));
            assertThat(run.getOutcome(), is(equalTo(ScriptRunRecorder.OUTCOME_FAILED)));
            assertThat(run.getCreateTimestamp(), is(notNullValue()));
            assertThat(run.getScripts(), hasSize(1));
            ScriptsRunScript script = run.getScripts().get(0);
            assertThat(script.getOrdinal(), is(0));
            assertThat(script.getScriptName(), is(equalTo("my-script")));
            assertThat(script.getScriptType(), is(equalTo("standalone")));
            assertThat(script.getSteps(), hasSize(1));
            assertThat(script.getSteps().get(0).getOrdinal(), is(0));
            ScriptsRunOutput out = script.getSteps().get(0).getOutputs().get(0);
            assertThat(out.getMessage(), is(equalTo("raw error")));
            assertThat(out.getKind(), is(equalTo(ScriptRunRecorder.OUTPUT_KIND_ERROR)));
            verify(tx).begin();
            verify(tx).commit();
            verify(pm).close();
        }
    }

    @Test
    void shouldPersistFailedRunWithStructuredFailureStep() {
        try (MockedStatic<TableJdo> tableJdo = mockStatic(TableJdo.class)) {
            PersistenceManagerFactory pmf = mock(PersistenceManagerFactory.class);
            PersistenceManager pm = mock(PersistenceManager.class);
            Transaction tx = mock(Transaction.class);
            tableJdo.when(TableJdo::getPmf).thenReturn(pmf);
            given(pmf.getPersistenceManager()).willReturn(pm);
            given(pm.currentTransaction()).willReturn(tx);
            given(tx.isActive()).willReturn(false);

            ScriptRunRecorder.recordFailedRun(
                    "summary",
                    List.of(
                            new ScriptRunRecorder.RunScript(
                                    "my-script",
                                    "standalone",
                                    new ScriptRunRecorder.FailureStep(
                                            13, "ZestClientElementClick"))),
                    "detail line");

            @SuppressWarnings("rawtypes")
            ArgumentCaptor<Object> captor = ArgumentCaptor.forClass(Object.class);
            verify(pm, times(1)).makePersistent(captor.capture());
            ScriptsRun run =
                    captor.getAllValues().stream()
                            .filter(ScriptsRun.class::isInstance)
                            .map(ScriptsRun.class::cast)
                            .findFirst()
                            .orElseThrow();
            assertThat(run.getScripts(), hasSize(1));
            ScriptsRunScript script = run.getScripts().get(0);
            assertThat(script.getScriptName(), is(equalTo("my-script")));
            assertThat(script.getSteps(), hasSize(1));
            ScriptsRunStep step = script.getSteps().get(0);
            assertThat(script.getOrdinal(), is(0));
            assertThat(step.getOrdinal(), is(0));
            assertThat(step.getSourceStepIndex(), is(equalTo(13)));
            assertThat(step.getLine(), is(equalTo("ZestClientElementClick")));
            assertThat(step.getOutputs().get(0).getOrdinal(), is(0));
            verify(tx).begin();
            verify(tx).commit();
            verify(pm).close();
        }
    }

    @Test
    void shouldPersistFailureOnlyOnScriptWithFailureSet() {
        try (MockedStatic<TableJdo> tableJdo = mockStatic(TableJdo.class)) {
            PersistenceManagerFactory pmf = mock(PersistenceManagerFactory.class);
            PersistenceManager pm = mock(PersistenceManager.class);
            Transaction tx = mock(Transaction.class);
            tableJdo.when(TableJdo::getPmf).thenReturn(pmf);
            given(pmf.getPersistenceManager()).willReturn(pm);
            given(pm.currentTransaction()).willReturn(tx);
            given(tx.isActive()).willReturn(false);

            ScriptRunRecorder.recordFailedRun(
                    "summary",
                    List.of(
                            new ScriptRunRecorder.RunScript("first", "standalone", null),
                            new ScriptRunRecorder.RunScript(
                                    "second",
                                    "standalone",
                                    new ScriptRunRecorder.FailureStep(5, "Click")),
                            new ScriptRunRecorder.RunScript("third", "standalone", null)),
                    "detail");

            @SuppressWarnings("rawtypes")
            ArgumentCaptor<Object> captor = ArgumentCaptor.forClass(Object.class);
            verify(pm, times(1)).makePersistent(captor.capture());
            ScriptsRun run =
                    captor.getAllValues().stream()
                            .filter(ScriptsRun.class::isInstance)
                            .map(ScriptsRun.class::cast)
                            .findFirst()
                            .orElseThrow();
            assertThat(run.getScripts(), hasSize(3));
            assertThat(run.getScripts().get(0).getOrdinal(), is(0));
            assertThat(run.getScripts().get(0).getScriptName(), is(equalTo("first")));
            assertThat(run.getScripts().get(0).getSteps(), hasSize(0));
            assertThat(run.getScripts().get(1).getOrdinal(), is(1));
            assertThat(run.getScripts().get(1).getScriptName(), is(equalTo("second")));
            assertThat(run.getScripts().get(1).getSteps(), hasSize(1));
            assertThat(run.getScripts().get(1).getSteps().get(0).getSourceStepIndex(), is(5));
            assertThat(run.getScripts().get(2).getOrdinal(), is(2));
            assertThat(run.getScripts().get(2).getScriptName(), is(equalTo("third")));
            assertThat(run.getScripts().get(2).getSteps(), hasSize(0));
        }
    }
}
