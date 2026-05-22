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
import java.util.Map;
import javax.jdo.FetchGroup;
import javax.jdo.FetchPlan;
import javax.jdo.PersistenceManager;
import javax.jdo.PersistenceManagerFactory;
import javax.jdo.Query;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.extension.scripts.report.ScriptRunReportData;

/** Loads persisted script runs for report generation. */
public final class ScriptRunReportQuery {

    private static final Logger LOGGER = LogManager.getLogger(ScriptRunReportQuery.class);

    private static final String RUNS_WITH_ERROR_FILTER =
            "this.scripts.contains(s) && s.steps.contains(st)"
                    + " && st.outputs.contains(o) && o.kind == :kind";

    private static final String RUNS_WITH_ERROR_VARIABLES =
            "org.zaproxy.zap.extension.scripts.internal.db.ScriptsRunScript s;"
                    + " org.zaproxy.zap.extension.scripts.internal.db.ScriptsRunStep st;"
                    + " org.zaproxy.zap.extension.scripts.internal.db.ScriptsRunOutput o";

    private static final String SCREENSHOT_FETCH_GROUP = "scriptDiagnosticsScreenshots";

    private ScriptRunReportQuery() {}

    @SuppressWarnings("try")
    public static List<ScriptRunReportData.Run> loadRunsForReport(
            boolean includeOutputSteps, boolean includeScreenshots) {
        PersistenceManagerFactory pmf = TableJdo.getPmf();
        if (pmf == null) {
            return List.of();
        }
        PersistenceManager pm = pmf.getPersistenceManager();
        try {
            applyScreenshotFetchGroup(pmf, pm, includeScreenshots);
            try (Query<ScriptsRun> runQuery = pm.newQuery(ScriptsRun.class)) {
                runQuery.setOrdering("id ascending");
                if (!includeOutputSteps) {
                    runQuery.setFilter(RUNS_WITH_ERROR_FILTER);
                    runQuery.declareVariables(RUNS_WITH_ERROR_VARIABLES);
                    runQuery.setNamedParameters(
                            Map.of("kind", ScriptRunRecorder.OUTPUT_KIND_ERROR));
                }
                return runQuery.executeList().stream()
                        .map(run -> materializeRun(run, includeOutputSteps, includeScreenshots))
                        .toList();
            }
        } catch (Exception e) {
            LOGGER.warn("Failed to load script runs for report.", e);
            return List.of();
        } finally {
            pm.close();
        }
    }

    /**
     * When screenshots are requested, add {@code screenshot} to a dynamic fetch group on this PM's
     * fetch plan so base64 blobs load with the query instead of via per-step lazy fetch. When not
     * requested, the field is left alone — {@link #screenshotData} must not touch it.
     */
    private static void applyScreenshotFetchGroup(
            PersistenceManagerFactory pmf, PersistenceManager pm, boolean includeScreenshots) {
        if (!includeScreenshots) {
            return;
        }
        FetchGroup fetchGroup = pmf.getFetchGroup(ScriptsRunStep.class, SCREENSHOT_FETCH_GROUP);
        if (!fetchGroup.getMembers().contains("screenshot")) {
            fetchGroup.addMember("screenshot");
        }
        FetchPlan fetchPlan = pm.getFetchPlan();
        fetchPlan.addGroup(SCREENSHOT_FETCH_GROUP);
    }

    private static ScriptRunReportData.Run materializeRun(
            ScriptsRun run, boolean includeOutputSteps, boolean includeScreenshots) {
        List<ScriptRunReportData.Script> scripts = new ArrayList<>();
        for (ScriptsRunScript sr : run.getScripts()) {
            scripts.add(materializeScript(sr, includeOutputSteps, includeScreenshots));
        }
        return new ScriptRunReportData.Run(
                run.getCreateTimestamp().toString(), run.getOutcome(), run.getSummary(), scripts);
    }

    private static ScriptRunReportData.Script materializeScript(
            ScriptsRunScript sr, boolean includeOutputSteps, boolean includeScreenshots) {
        List<ScriptRunReportData.Step> reportSteps =
                sr.getSteps().stream()
                        .filter(st -> includeOutputSteps || hasErrorOutput(st))
                        .map(st -> materializeStep(st, includeScreenshots))
                        .toList();
        return new ScriptRunReportData.Script(
                sr.getOrdinal() + 1, sr.getScriptName(), sr.getScriptType(), reportSteps);
    }

    private static boolean hasErrorOutput(ScriptsRunStep st) {
        return st.getOutputs().stream()
                .anyMatch(o -> ScriptRunRecorder.OUTPUT_KIND_ERROR.equals(o.getKind()));
    }

    private static ScriptRunReportData.Step materializeStep(
            ScriptsRunStep st, boolean includeScreenshots) {
        List<ScriptRunReportData.Output> reportOuts =
                st.getOutputs().stream()
                        .map(o -> new ScriptRunReportData.Output(o.getKind(), o.getMessage()))
                        .toList();
        return new ScriptRunReportData.Step(
                st.getSourceStepIndex(),
                st.getLine(),
                reportOuts,
                screenshotData(st, includeScreenshots));
    }

    private static String screenshotData(ScriptsRunStep st, boolean includeScreenshots) {
        if (!includeScreenshots) {
            return null;
        }
        ScriptsRunStepScreenshot screenshot = st.getScreenshot();
        return screenshot != null ? screenshot.getData() : null;
    }
}
