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

    private ScriptRunReportQuery() {}

    public static List<ScriptRunReportData.Run> loadRunsForReport(boolean includeScreenshots) {
        PersistenceManagerFactory pmf = TableJdo.getPmf();
        if (pmf == null) {
            return List.of();
        }
        PersistenceManager pm = pmf.getPersistenceManager();
        try {
            return queryRuns(pm, includeScreenshots);
        } catch (Exception e) {
            LOGGER.warn("Failed to load script runs for report.", e);
            return List.of();
        } finally {
            pm.close();
        }
    }

    @SuppressWarnings("try")
    private static List<ScriptRunReportData.Run> queryRuns(
            PersistenceManager pm, boolean includeScreenshots) throws Exception {
        try (Query<ScriptsRun> runQuery = pm.newQuery(ScriptsRun.class)) {
            runQuery.setOrdering("id ascending");
            return runQuery.executeList().stream()
                    .map(run -> materializeRun(run, includeScreenshots))
                    .toList();
        }
    }

    private static ScriptRunReportData.Run materializeRun(
            ScriptsRun run, boolean includeScreenshots) {
        List<ScriptRunReportData.Script> scripts = new ArrayList<>();
        for (ScriptsRunScript sr : run.getScripts()) {
            scripts.add(materializeScript(sr, includeScreenshots));
        }
        return new ScriptRunReportData.Run(
                run.getCreateTimestamp().toString(), run.getOutcome(), run.getSummary(), scripts);
    }

    private static ScriptRunReportData.Script materializeScript(
            ScriptsRunScript sr, boolean includeScreenshots) {
        List<ScriptRunReportData.Step> reportSteps =
                sr.getSteps().stream()
                        .map(step -> materializeStep(step, includeScreenshots))
                        .toList();
        return new ScriptRunReportData.Script(
                sr.getOrdinal() + 1, sr.getScriptName(), sr.getScriptType(), reportSteps);
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
