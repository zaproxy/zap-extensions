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
import static org.mockito.Mockito.verify;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import javax.jdo.PersistenceManager;
import javax.jdo.PersistenceManagerFactory;
import javax.jdo.Query;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.zaproxy.zap.extension.scripts.internal.db.ScriptRunReportQuery.Options;
import org.zaproxy.zap.extension.scripts.report.ScriptRunReportData;

/** Unit tests for {@link ScriptRunReportQuery}. */
class ScriptRunReportQueryUnitTest {

    @Test
    void shouldUsePersistedOrdinalForReportOrder() {
        ScriptsRun run = new ScriptsRun();
        run.setCreateTimestamp(Instant.parse("2026-04-01T12:00:00Z"));
        run.setOutcome(ScriptRunRecorder.OUTCOME_FAILED);
        run.setSummary("summary");

        run.getScripts().add(scriptRow(run, 0, "first"));
        run.getScripts().add(scriptRow(run, 1, "second"));

        try (MockedStatic<TableJdo> tableJdo = mockStatic(TableJdo.class)) {
            Query<ScriptsRun> runQuery = mock();
            PersistenceManager pm = stubPersistence(tableJdo, runQuery);
            given(runQuery.executeList()).willReturn(List.of(run));

            List<ScriptRunReportData.Run> rows =
                    ScriptRunReportQuery.loadRunsForReport(new Options(false, false));

            assertThat(rows, hasSize(1));
            List<ScriptRunReportData.Script> scripts = rows.get(0).scripts();
            assertThat(scripts, hasSize(2));
            assertThat(scripts.get(0).order(), is(equalTo(1)));
            assertThat(scripts.get(0).scriptName(), is(equalTo("first")));
            assertThat(scripts.get(1).order(), is(equalTo(2)));
            assertThat(scripts.get(1).scriptName(), is(equalTo("second")));
            verify(pm).close();
        }
    }

    @Test
    void shouldLoadRunsForReport() {
        ScriptsRun run = runWithScreenshotStep();

        try (MockedStatic<TableJdo> tableJdo = mockStatic(TableJdo.class)) {
            Query<ScriptsRun> runQuery = mock();
            stubPersistence(tableJdo, runQuery);
            given(runQuery.executeList()).willReturn(List.of(run));

            ScriptRunReportData.Step withScreenshot =
                    ScriptRunReportQuery.loadRunsForReport(new Options(true, false))
                            .get(0)
                            .scripts()
                            .get(0)
                            .steps()
                            .get(0);

            assertThat(withScreenshot.screenshot(), is(equalTo("pngdata")));
            assertThat(withScreenshot.outputs(), hasSize(1));
            assertThat(
                    withScreenshot.outputs().get(0).kind(),
                    is(equalTo(ScriptRunRecorder.OUTPUT_KIND_ERROR)));

            ScriptRunReportData.Step withoutScreenshot =
                    ScriptRunReportQuery.loadRunsForReport(new Options(false, false))
                            .get(0)
                            .scripts()
                            .get(0)
                            .steps()
                            .get(0);

            assertThat(withoutScreenshot.screenshot(), is(nullValue()));
            assertThat(withoutScreenshot.outputs(), hasSize(1));
        }
    }

    @Test
    void shouldOmitStepStdoutWhenOutputSectionDisabled() {
        ScriptsRun run = runWithStepStdout();

        try (MockedStatic<TableJdo> tableJdo = mockStatic(TableJdo.class)) {
            Query<ScriptsRun> runQuery = mock();
            stubPersistence(tableJdo, runQuery);
            given(runQuery.executeList()).willReturn(List.of(run));

            assertThat(
                    ScriptRunReportQuery.loadRunsForReport(new Options(false, false)), hasSize(0));

            ScriptRunReportData.Script withStdout =
                    ScriptRunReportQuery.loadRunsForReport(new Options(false, true))
                            .get(0)
                            .scripts()
                            .get(0);

            assertThat(withStdout.steps(), hasSize(1));
            assertThat(withStdout.steps().get(0).sourceStepIndex(), is(equalTo(3)));
            assertThat(withStdout.steps().get(0).line(), is(equalTo("ZestActionPrint")));
            assertThat(withStdout.steps().get(0).outputs(), hasSize(1));
            assertThat(withStdout.steps().get(0).outputs().get(0).kind(), is(equalTo("OUTPUT")));
            assertThat(
                    withStdout.steps().get(0).outputs().get(0).message(), is(equalTo("logged in")));
        }
    }

    @Test
    void shouldIncludeSuccessfulRunWhenOutputDisabledButScreenshotPresent() {
        ScriptsRun run = runWithSuccessfulScreenshotStep();

        try (MockedStatic<TableJdo> tableJdo = mockStatic(TableJdo.class)) {
            Query<ScriptsRun> runQuery = mock();
            stubPersistence(tableJdo, runQuery);
            given(runQuery.executeList()).willReturn(List.of(run));

            ScriptRunReportData.Step step =
                    ScriptRunReportQuery.loadRunsForReport(new Options(true, false))
                            .get(0)
                            .scripts()
                            .get(0)
                            .steps()
                            .get(0);

            assertThat(step.outputs(), hasSize(0));
            assertThat(step.screenshot(), is(equalTo("pngdata")));
        }
    }

    @Test
    void shouldFilterReportDataRunsUsingSameRulesAsPersistedQuery() {
        ScriptRunReportData.Run run =
                new ScriptRunReportData.Run(
                        "2026-04-03T10:00:00Z",
                        ScriptRunRecorder.OUTCOME_FAILED,
                        "Job: failed after log",
                        List.of(
                                new ScriptRunReportData.Script(
                                        1,
                                        "zest-script",
                                        "standalone",
                                        List.of(
                                                new ScriptRunReportData.Step(
                                                        3,
                                                        "ZestActionPrint",
                                                        List.of(
                                                                new ScriptRunReportData.Output(
                                                                        ScriptRunRecorder
                                                                                .OUTPUT_KIND_OUTPUT,
                                                                        "logged in"),
                                                                new ScriptRunReportData.Output(
                                                                        ScriptRunRecorder
                                                                                .OUTPUT_KIND_ERROR,
                                                                        "boom")),
                                                        null)))));

        List<ScriptRunReportData.Run> filtered =
                ScriptRunReportQuery.filterRunsForReport(List.of(run), new Options(false, false));

        assertThat(filtered, hasSize(1));
        assertThat(filtered.get(0).scripts().get(0).steps().get(0).outputs(), hasSize(1));
        assertThat(
                filtered.get(0).scripts().get(0).steps().get(0).outputs().get(0).kind(),
                is(equalTo(ScriptRunRecorder.OUTPUT_KIND_ERROR)));
    }

    private static PersistenceManager stubPersistence(
            MockedStatic<TableJdo> tableJdo, Query<ScriptsRun> runQuery) {
        PersistenceManagerFactory pmf = mock(PersistenceManagerFactory.class);
        PersistenceManager pm = mock(PersistenceManager.class);
        tableJdo.when(TableJdo::getPmf).thenReturn(pmf);
        given(pmf.getPersistenceManager()).willReturn(pm);
        given(pm.newQuery(ScriptsRun.class)).willReturn(runQuery);
        return pm;
    }

    private static ScriptsRun runWithStepStdout() {
        ScriptsRun run = new ScriptsRun();
        run.setCreateTimestamp(Instant.parse("2026-04-01T12:00:00Z"));
        run.setOutcome(ScriptRunRecorder.OUTCOME_SUCCESS);
        run.setSummary("summary");

        ScriptsRunScript script = scriptRow(run, 0, "zest-script");
        ScriptsRunStep step = new ScriptsRunStep();
        step.setRunScript(script);
        step.setOrdinal(0);
        step.setSourceStepIndex(3);
        step.setLine("ZestActionPrint");
        ScriptsRunOutput output = new ScriptsRunOutput();
        output.setRunStep(step);
        output.setOrdinal(0);
        output.setKind(ScriptRunRecorder.OUTPUT_KIND_OUTPUT);
        output.setMessage("logged in");
        step.getOutputs().add(output);
        script.getSteps().add(step);
        run.getScripts().add(script);
        return run;
    }

    private static ScriptsRun runWithSuccessfulScreenshotStep() {
        ScriptsRun run = new ScriptsRun();
        run.setCreateTimestamp(Instant.parse("2026-04-02T08:30:00Z"));
        run.setOutcome(ScriptRunRecorder.OUTCOME_SUCCESS);
        run.setSummary("summary");

        ScriptsRunScript script = scriptRow(run, 0, "zest-script");
        run.getScripts().add(script);
        ScriptsRunStep step = new ScriptsRunStep();
        step.setRunScript(script);
        step.setOrdinal(0);
        step.setSourceStepIndex(7);
        step.setLine("ZestClientClick");
        ScriptsRunOutput stdout = new ScriptsRunOutput();
        stdout.setRunStep(step);
        stdout.setOrdinal(0);
        stdout.setKind(ScriptRunRecorder.OUTPUT_KIND_OUTPUT);
        stdout.setMessage("logged in");
        step.getOutputs().add(stdout);
        ScriptsRunStepScreenshot screenshot = new ScriptsRunStepScreenshot();
        screenshot.setRunStep(step);
        screenshot.setData("pngdata");
        step.setScreenshot(screenshot);
        script.getSteps().add(step);
        return run;
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
        ScriptsRunOutput error = new ScriptsRunOutput();
        error.setRunStep(step);
        error.setOrdinal(0);
        error.setKind(ScriptRunRecorder.OUTPUT_KIND_ERROR);
        error.setMessage("step failed");
        step.getOutputs().add(error);
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
