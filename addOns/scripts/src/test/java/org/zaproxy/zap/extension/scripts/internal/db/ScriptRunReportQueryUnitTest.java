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
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import javax.jdo.PersistenceManager;
import javax.jdo.PersistenceManagerFactory;
import javax.jdo.Query;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.zaproxy.zap.extension.scripts.report.ScriptRunReportData;

/** Unit tests for {@link ScriptRunReportQuery}. */
class ScriptRunReportQueryUnitTest {

    @Test
    void shouldFilterRunsWithErrorsAtQueryWhenOutputStepsExcluded() {
        try (MockedStatic<TableJdo> tableJdo = mockStatic(TableJdo.class)) {
            PersistenceManagerFactory pmf = mock(PersistenceManagerFactory.class);
            PersistenceManager pm = mock(PersistenceManager.class);
            @SuppressWarnings("unchecked")
            Query<ScriptsRun> query = mock(Query.class);
            tableJdo.when(TableJdo::getPmf).thenReturn(pmf);
            given(pmf.getPersistenceManager()).willReturn(pm);
            given(pm.newQuery(ScriptsRun.class)).willReturn(query);
            given(query.executeList()).willReturn(List.of());

            ScriptRunReportQuery.loadRunsForReport(false);

            verify(query)
                    .setFilter(
                            "this.scripts.contains(s) && s.steps.contains(st)"
                                    + " && st.outputs.contains(o) && o.kind == :kind");
            verify(query)
                    .declareVariables(
                            "org.zaproxy.zap.extension.scripts.internal.db.ScriptsRunScript s;"
                                    + " org.zaproxy.zap.extension.scripts.internal.db.ScriptsRunStep st;"
                                    + " org.zaproxy.zap.extension.scripts.internal.db.ScriptsRunOutput o");
            verify(query)
                    .setNamedParameters(
                            java.util.Map.of("kind", ScriptRunRecorder.OUTPUT_KIND_ERROR));
        }
    }

    @Test
    void shouldNotFilterRunsAtQueryWhenOutputStepsIncluded() {
        try (MockedStatic<TableJdo> tableJdo = mockStatic(TableJdo.class)) {
            PersistenceManagerFactory pmf = mock(PersistenceManagerFactory.class);
            PersistenceManager pm = mock(PersistenceManager.class);
            @SuppressWarnings("unchecked")
            Query<ScriptsRun> query = mock(Query.class);
            tableJdo.when(TableJdo::getPmf).thenReturn(pmf);
            given(pmf.getPersistenceManager()).willReturn(pm);
            given(pm.newQuery(ScriptsRun.class)).willReturn(query);
            given(query.executeList()).willReturn(List.of());

            ScriptRunReportQuery.loadRunsForReport(true);

            verify(query, never()).setFilter(org.mockito.ArgumentMatchers.anyString());
            verify(query, never()).declareVariables(org.mockito.ArgumentMatchers.anyString());
            verify(query, never()).setNamedParameters(org.mockito.ArgumentMatchers.any());
        }
    }

    @Test
    void shouldExcludeOutputOnlyStepsWhenOutputStepsExcluded() {
        ScriptsRun run = new ScriptsRun();
        run.setCreateTimestamp(Instant.parse("2026-04-01T12:00:00Z"));
        run.setOutcome(ScriptRunRecorder.OUTCOME_SUCCESS);
        run.setSummary("summary");
        ScriptsRunScript script = scriptRow(run, 0, "print_only");
        ScriptsRunStep outputStep = new ScriptsRunStep();
        outputStep.setRunScript(script);
        outputStep.setOrdinal(0);
        outputStep.setSourceStepIndex(-1);
        outputStep.setLine("");
        ScriptsRunOutput output = new ScriptsRunOutput();
        output.setRunStep(outputStep);
        output.setOrdinal(0);
        output.setKind(ScriptRunRecorder.OUTPUT_KIND_OUTPUT);
        output.setMessage("hello");
        outputStep.getOutputs().add(output);
        script.getSteps().add(outputStep);
        run.getScripts().add(script);

        try (MockedStatic<TableJdo> tableJdo = mockStatic(TableJdo.class)) {
            PersistenceManagerFactory pmf = mock(PersistenceManagerFactory.class);
            PersistenceManager pm = mock(PersistenceManager.class);
            @SuppressWarnings("unchecked")
            Query<ScriptsRun> query = mock(Query.class);
            tableJdo.when(TableJdo::getPmf).thenReturn(pmf);
            given(pmf.getPersistenceManager()).willReturn(pm);
            given(pm.newQuery(ScriptsRun.class)).willReturn(query);
            given(query.executeList()).willReturn(List.of(run));

            List<ScriptRunReportData.Run> rows = ScriptRunReportQuery.loadRunsForReport(false);

            assertThat(rows, hasSize(1));
            assertThat(rows.get(0).scripts().get(0).steps(), hasSize(0));
        }
    }

    @Test
    void shouldUsePersistedOrdinalForReportOrder() {
        // Given
        ScriptsRun run = new ScriptsRun();
        run.setCreateTimestamp(Instant.parse("2026-04-01T12:00:00Z"));
        run.setOutcome(ScriptRunRecorder.OUTCOME_FAILED);
        run.setSummary("summary");
        run.getScripts().add(scriptRow(run, 0, "first"));
        run.getScripts().add(scriptRow(run, 1, "second"));

        try (MockedStatic<TableJdo> tableJdo = mockStatic(TableJdo.class)) {
            PersistenceManagerFactory pmf = mock(PersistenceManagerFactory.class);
            PersistenceManager pm = mock(PersistenceManager.class);
            @SuppressWarnings("unchecked")
            Query<ScriptsRun> query = mock(Query.class);
            tableJdo.when(TableJdo::getPmf).thenReturn(pmf);
            given(pmf.getPersistenceManager()).willReturn(pm);
            given(pm.newQuery(ScriptsRun.class)).willReturn(query);
            given(query.executeList()).willReturn(List.of(run));

            // When
            List<ScriptRunReportData.Run> rows = ScriptRunReportQuery.loadRunsForReport(true);

            // Then
            assertThat(rows, hasSize(1));
            List<ScriptRunReportData.Script> scripts = rows.get(0).scripts();
            assertThat(scripts, hasSize(2));
            assertThat(scripts.get(0).order(), is(equalTo(1)));
            assertThat(scripts.get(0).scriptName(), is(equalTo("first")));
            assertThat(scripts.get(1).order(), is(equalTo(2)));
            assertThat(scripts.get(1).scriptName(), is(equalTo("second")));
        }
    }

    private static ScriptsRunScript scriptRow(ScriptsRun run, int ordinal, String name) {
        ScriptsRunScript row = new ScriptsRunScript();
        row.setRun(run);
        row.setOrdinal(ordinal);
        row.setScriptName(name);
        row.setScriptType("standalone");
        row.setSteps(new ArrayList<>());
        return row;
    }
}
