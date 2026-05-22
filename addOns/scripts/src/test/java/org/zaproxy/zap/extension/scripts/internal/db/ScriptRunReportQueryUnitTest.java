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
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.jdo.FetchGroup;
import javax.jdo.FetchPlan;
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
        // Given
        ScriptsRun failedRun = runWithScreenshotStep();

        try (MockedStatic<TableJdo> tableJdo = mockStatic(TableJdo.class)) {
            PersistenceManagerFactory pmf = mock(PersistenceManagerFactory.class);
            PersistenceManager pm = mock(PersistenceManager.class);
            @SuppressWarnings("unchecked")
            Query<ScriptsRun> query = mock(Query.class);
            tableJdo.when(TableJdo::getPmf).thenReturn(pmf);
            given(pmf.getPersistenceManager()).willReturn(pm);
            given(pm.newQuery(ScriptsRun.class)).willReturn(query);
            given(query.executeList()).willReturn(List.of(failedRun));

            // When
            List<ScriptRunReportData.Run> rows =
                    ScriptRunReportQuery.loadRunsForReport(false, false);

            // Then
            assertThat(rows, hasSize(1));
            assertThat(rows.get(0).outcome(), is(equalTo(ScriptRunRecorder.OUTCOME_FAILED)));

            verify(query)
                    .setFilter(
                            "this.scripts.contains(s) && s.steps.contains(st)"
                                    + " && st.outputs.contains(o) && o.kind == :kind");
            verify(query)
                    .declareVariables(
                            "org.zaproxy.zap.extension.scripts.internal.db.ScriptsRunScript s;"
                                    + " org.zaproxy.zap.extension.scripts.internal.db.ScriptsRunStep st;"
                                    + " org.zaproxy.zap.extension.scripts.internal.db.ScriptsRunOutput o");
            verify(query).setNamedParameters(Map.of("kind", ScriptRunRecorder.OUTPUT_KIND_ERROR));
        }
    }

    @Test
    void shouldNotFilterRunsAtQueryWhenOutputStepsIncluded() {
        // Given
        try (MockedStatic<TableJdo> tableJdo = mockStatic(TableJdo.class)) {
            PersistenceManagerFactory pmf = mock(PersistenceManagerFactory.class);
            PersistenceManager pm = mock(PersistenceManager.class);
            @SuppressWarnings("unchecked")
            Query<ScriptsRun> query = mock(Query.class);
            tableJdo.when(TableJdo::getPmf).thenReturn(pmf);
            given(pmf.getPersistenceManager()).willReturn(pm);
            given(pm.newQuery(ScriptsRun.class)).willReturn(query);
            given(query.executeList()).willReturn(List.of());

            // When
            ScriptRunReportQuery.loadRunsForReport(true, false);

            // Then
            verify(query, never()).setFilter(org.mockito.ArgumentMatchers.anyString());
            verify(query, never()).declareVariables(org.mockito.ArgumentMatchers.anyString());
            verify(query, never()).setNamedParameters(org.mockito.ArgumentMatchers.any());
        }
    }

    @Test
    void shouldNotLoadSuccessOutputOnlyRunWhenOutputStepsExcluded() {
        // Given — JDO filter requires ERROR output; SUCCESS output-only runs do not match
        try (MockedStatic<TableJdo> tableJdo = mockStatic(TableJdo.class)) {
            PersistenceManagerFactory pmf = mock(PersistenceManagerFactory.class);
            PersistenceManager pm = mock(PersistenceManager.class);
            @SuppressWarnings("unchecked")
            Query<ScriptsRun> query = mock(Query.class);
            tableJdo.when(TableJdo::getPmf).thenReturn(pmf);
            given(pmf.getPersistenceManager()).willReturn(pm);
            given(pm.newQuery(ScriptsRun.class)).willReturn(query);
            given(query.executeList()).willReturn(List.of());

            // When
            List<ScriptRunReportData.Run> rows =
                    ScriptRunReportQuery.loadRunsForReport(false, false);

            // Then
            assertThat(rows, hasSize(0));
            verify(query)
                    .setFilter(
                            "this.scripts.contains(s) && s.steps.contains(st)"
                                    + " && st.outputs.contains(o) && o.kind == :kind");
        }
    }

    @Test
    void shouldExcludeOutputOnlyStepsWhenOutputStepsExcluded() {
        // Given
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

            // When
            List<ScriptRunReportData.Run> rows =
                    ScriptRunReportQuery.loadRunsForReport(false, false);

            // Then
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
            List<ScriptRunReportData.Run> rows =
                    ScriptRunReportQuery.loadRunsForReport(true, false);

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

    @Test
    void shouldLoadRunsForReport() {
        // Given
        ScriptsRun run = runWithScreenshotStep();

        try (MockedStatic<TableJdo> tableJdo = mockStatic(TableJdo.class)) {
            PersistenceManagerFactory pmf = mock(PersistenceManagerFactory.class);
            PersistenceManager pm = mock(PersistenceManager.class);
            FetchGroup fetchGroup = mock(FetchGroup.class);
            FetchPlan fetchPlan = mock(FetchPlan.class);
            Set<String> fetchGroupMembers = new HashSet<>();
            @SuppressWarnings("unchecked")
            Query<ScriptsRun> query = mock(Query.class);
            tableJdo.when(TableJdo::getPmf).thenReturn(pmf);
            given(pmf.getPersistenceManager()).willReturn(pm);
            given(pmf.getFetchGroup(ScriptsRunStep.class, "scriptDiagnosticsScreenshots"))
                    .willReturn(fetchGroup);
            given(fetchGroup.getMembers()).willReturn(fetchGroupMembers);
            given(pm.getFetchPlan()).willReturn(fetchPlan);
            given(pm.newQuery(ScriptsRun.class)).willReturn(query);
            given(query.executeList()).willReturn(List.of(run));

            // When
            ScriptRunReportData.Step withScreenshot =
                    ScriptRunReportQuery.loadRunsForReport(false, true)
                            .get(0)
                            .scripts()
                            .get(0)
                            .steps()
                            .get(0);

            // Then
            assertThat(withScreenshot.screenshot(), is(equalTo("pngdata")));
            verify(fetchPlan).addGroup("scriptDiagnosticsScreenshots");

            // When
            ScriptRunReportData.Step withoutScreenshot =
                    ScriptRunReportQuery.loadRunsForReport(false, false)
                            .get(0)
                            .scripts()
                            .get(0)
                            .steps()
                            .get(0);

            // Then
            assertThat(withoutScreenshot.screenshot(), is(nullValue()));
        }
    }

    private static ScriptsRun runWithScreenshotStep() {
        ScriptsRun run = new ScriptsRun();
        run.setCreateTimestamp(Instant.parse("2026-04-01T12:00:00Z"));
        run.setOutcome(ScriptRunRecorder.OUTCOME_FAILED);
        run.setSummary("summary");

        ScriptsRunScript script = scriptRow(run, 0, "zest-script");
        run.getScripts().add(script);
        ScriptsRunStep step = new ScriptsRunStep();
        step.setRunScript(script);
        step.setOrdinal(0);
        step.setSourceStepIndex(7);
        step.setLine("ZestClientClick");
        ScriptsRunOutput errorOutput = new ScriptsRunOutput();
        errorOutput.setRunStep(step);
        errorOutput.setOrdinal(0);
        errorOutput.setKind(ScriptRunRecorder.OUTPUT_KIND_ERROR);
        errorOutput.setMessage("click failed");
        step.getOutputs().add(errorOutput);
        ScriptsRunStepScreenshot screenshot = new ScriptsRunStepScreenshot();
        screenshot.setRunStep(step);
        screenshot.setData("pngdata");
        step.setScreenshot(screenshot);
        script.getSteps().add(step);
        return run;
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
