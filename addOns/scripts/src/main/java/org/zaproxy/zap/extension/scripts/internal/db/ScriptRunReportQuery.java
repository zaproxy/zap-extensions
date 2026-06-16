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

import java.util.ArrayList;
import java.util.List;
import javax.jdo.PersistenceManager;
import javax.jdo.PersistenceManagerFactory;
import javax.jdo.Query;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.extension.scripts.report.ScriptRunReportData;

/** Loads persisted script runs for report generation. */
public final class ScriptRunReportQuery {

    private static final Logger LOGGER = LogManager.getLogger(ScriptRunReportQuery.class);

    public record Options(boolean includeScreenshots, boolean includeScriptOutput) {}

    private ScriptRunReportQuery() {}

    public static List<ScriptRunReportData.Run> loadRunsForReport(Options options) {
        PersistenceManagerFactory pmf = TableJdo.getPmf();
        if (pmf == null) {
            return List.of();
        }
        PersistenceManager pm = pmf.getPersistenceManager();
        try {
            return queryRuns(pm, options);
        } catch (Exception e) {
            LOGGER.warn("Failed to load script runs for report.", e);
            return List.of();
        } finally {
            pm.close();
        }
    }

    /**
     * Applies report section options to in-memory runs for unit tests, without querying the
     * persistence layer.
     */
    public static List<ScriptRunReportData.Run> filterRunsForReport(
            List<ScriptRunReportData.Run> runs, Options options) {
        return runs.stream()
                .map(run -> materializeRunFromReportData(run, options))
                .filter(ScriptRunReportQuery::hasReportableContent)
                .toList();
    }

    @SuppressWarnings("try")
    private static List<ScriptRunReportData.Run> queryRuns(PersistenceManager pm, Options options)
            throws Exception {
        try (Query<ScriptsRun> runQuery = pm.newQuery(ScriptsRun.class)) {
            runQuery.setOrdering("id ascending");
            List<ScriptRunReportData.Run> runs = new ArrayList<>();
            for (ScriptsRun run : runQuery.executeList()) {
                runs.add(materializeRun(run, options));
            }
            return runs.stream().filter(ScriptRunReportQuery::hasReportableContent).toList();
        }
    }

    private static ScriptRunReportData.Run materializeRun(ScriptsRun run, Options options) {
        List<ScriptRunReportData.Script> scripts = new ArrayList<>();
        for (ScriptsRunScript sr : run.getScripts()) {
            scripts.add(materializeScript(sr, options));
        }
        return new ScriptRunReportData.Run(
                run.getCreateTimestamp().toString(), run.getOutcome(), run.getSummary(), scripts);
    }

    private static ScriptRunReportData.Run materializeRunFromReportData(
            ScriptRunReportData.Run run, Options options) {
        return new ScriptRunReportData.Run(
                run.created(),
                run.outcome(),
                run.summary(),
                run.scripts().stream()
                        .map(script -> materializeScriptFromReportData(script, options))
                        .toList());
    }

    private static ScriptRunReportData.Script materializeScript(
            ScriptsRunScript sr, Options options) {
        List<ScriptRunReportData.Step> reportSteps = new ArrayList<>();
        for (ScriptsRunStep step : sr.getSteps()) {
            ScriptRunReportData.Step reportStep = materializeStep(step, options);
            if (!reportStep.outputs().isEmpty() || reportStep.screenshot() != null) {
                reportSteps.add(reportStep);
            }
        }
        return new ScriptRunReportData.Script(
                sr.getOrdinal() + 1, sr.getScriptName(), sr.getScriptType(), reportSteps);
    }

    private static ScriptRunReportData.Script materializeScriptFromReportData(
            ScriptRunReportData.Script script, Options options) {
        List<ScriptRunReportData.Step> reportSteps =
                script.steps().stream()
                        .map(step -> materializeStepFromReportData(step, options))
                        .filter(step -> !step.outputs().isEmpty() || step.screenshot() != null)
                        .toList();
        return new ScriptRunReportData.Script(
                script.order(), script.scriptName(), script.scriptType(), reportSteps);
    }

    private static ScriptRunReportData.Step materializeStep(ScriptsRunStep st, Options options) {
        List<ScriptRunReportData.Output> reportOuts =
                loadOutputsForReport(st, options).stream()
                        .map(o -> new ScriptRunReportData.Output(o.getKind(), o.getMessage()))
                        .toList();
        return new ScriptRunReportData.Step(
                st.getSourceStepIndex(),
                st.getLine(),
                reportOuts,
                screenshotData(st, options.includeScreenshots()));
    }

    private static ScriptRunReportData.Step materializeStepFromReportData(
            ScriptRunReportData.Step step, Options options) {
        return new ScriptRunReportData.Step(
                step.sourceStepIndex(),
                step.line(),
                filterOutputsForReport(step.outputs(), options),
                screenshotData(step.screenshot(), options.includeScreenshots()));
    }

    private static List<ScriptsRunOutput> loadOutputsForReport(
            ScriptsRunStep step, Options options) {
        if (options.includeScriptOutput()) {
            return step.getOutputs();
        }
        return step.getOutputs().stream()
                .filter(o -> ScriptRunRecorder.OUTPUT_KIND_ERROR.equals(o.getKind()))
                .toList();
    }

    private static List<ScriptRunReportData.Output> filterOutputsForReport(
            List<ScriptRunReportData.Output> outputs, Options options) {
        return outputs.stream().filter(output -> includeOutput(output.kind(), options)).toList();
    }

    private static boolean includeOutput(String kind, Options options) {
        return options.includeScriptOutput() || ScriptRunRecorder.OUTPUT_KIND_ERROR.equals(kind);
    }

    private static String screenshotData(ScriptsRunStep st, boolean includeScreenshots) {
        if (!includeScreenshots) {
            return null;
        }
        ScriptsRunStepScreenshot screenshot = st.getScreenshot();
        return screenshot != null ? screenshot.getData() : null;
    }

    private static String screenshotData(String screenshotBase64, boolean includeScreenshots) {
        if (!includeScreenshots) {
            return null;
        }
        return screenshotBase64;
    }

    private static boolean hasReportableContent(ScriptRunReportData.Run run) {
        if (!ScriptRunRecorder.OUTCOME_SUCCESS.equals(run.outcome())) {
            return true;
        }
        return run.scripts().stream().anyMatch(script -> !script.steps().isEmpty());
    }
}
