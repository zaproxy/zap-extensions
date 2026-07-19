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

import java.time.Instant;
import java.util.List;
import javax.jdo.PersistenceManager;
import javax.jdo.PersistenceManagerFactory;
import javax.jdo.Transaction;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Persists script runs; persistence errors are logged and not rethrown. */
public final class ScriptRunRecorder {

    private static final Logger LOGGER = LogManager.getLogger(ScriptRunRecorder.class);

    public static final String OUTCOME_FAILED = "FAILED";
    public static final String OUTCOME_SUCCESS = "SUCCESS";
    public static final String OUTPUT_KIND_ERROR = "ERROR";
    public static final String OUTPUT_KIND_OUTPUT = "OUTPUT";

    /** One script row in a recorded run, in chain order. */
    public record RunScript(String scriptName, String scriptType, List<RunStep> steps) {

        public RunScript(String scriptName, String scriptType) {
            this(scriptName, scriptType, List.of());
        }
    }

    public record RunStep(
            int sourceStepIndex, String line, List<StepOutput> outputs, String screenshotBase64) {

        public RunStep(int sourceStepIndex, String line, List<StepOutput> outputs) {
            this(sourceStepIndex, line, outputs, null);
        }
    }

    public record StepOutput(int ordinal, String kind, String message) {}

    /**
     * {@code sourceStepIndex}: statement index in the failing script, or {@code -1}. {@code line}:
     * failing element type name.
     */
    public record FailureStep(int sourceStepIndex, String line, String screenshotBase64) {

        public FailureStep(int sourceStepIndex, String line) {
            this(sourceStepIndex, line, null);
        }
    }

    private ScriptRunRecorder() {}

    /** Persists one failed run; {@code scripts} must be non-empty and in chain order. */
    public static void recordFailedRun(String summary, List<RunScript> scripts) {
        recordRun(OUTCOME_FAILED, summary, scripts);
    }

    /** Persists one run; {@code scripts} must be non-empty and in chain order. */
    public static void recordRun(String outcome, String summary, List<RunScript> scripts) {
        String summaryToStore = StringUtils.defaultString(summary);
        if (scripts == null || scripts.isEmpty()) {
            return;
        }
        PersistenceManagerFactory pmf = TableJdo.getPmf();
        if (pmf == null) {
            return;
        }
        try {
            ScriptsRun run = new ScriptsRun();
            run.setCreateTimestamp(Instant.now());
            run.setOutcome(outcome);
            run.setSummary(summaryToStore);

            PersistenceManager pm = pmf.getPersistenceManager();
            Transaction tx = pm.currentTransaction();
            try {
                tx.begin();
                int scriptOrdinal = 0;
                for (RunScript runScript : scripts) {
                    ScriptsRunScript row = new ScriptsRunScript();
                    row.setRun(run);
                    row.setOrdinal(scriptOrdinal++);
                    row.setScriptName(StringUtils.defaultString(runScript.scriptName()));
                    row.setScriptType(StringUtils.defaultString(runScript.scriptType()));
                    run.getScripts().add(row);

                    int stepOrdinal = 0;
                    for (RunStep step : runScript.steps()) {
                        ScriptsRunStep st = new ScriptsRunStep();
                        st.setRunScript(row);
                        st.setOrdinal(stepOrdinal++);
                        st.setSourceStepIndex(step.sourceStepIndex());
                        st.setLine(StringUtils.defaultString(step.line()));
                        row.getSteps().add(st);

                        for (StepOutput output : step.outputs()) {
                            ScriptsRunOutput out = new ScriptsRunOutput();
                            out.setRunStep(st);
                            out.setOrdinal(output.ordinal());
                            out.setKind(output.kind());
                            out.setMessage(StringUtils.defaultString(output.message()));
                            st.getOutputs().add(out);
                        }

                        attachScreenshot(st, step.screenshotBase64());
                    }
                }

                pm.makePersistent(run);

                tx.commit();
            } finally {
                if (tx.isActive()) {
                    tx.rollback();
                }
                pm.close();
            }
        } catch (Exception e) {
            LOGGER.warn("Failed to persist script run: {}", e.getMessage(), e);
        }
    }

    public static void recordSingleScriptFailure(
            String scriptName,
            String scriptType,
            String summaryMessage,
            String outputDetailMessage,
            String screenshotBase64) {
        recordFailedRun(
                summaryMessage,
                List.of(
                        new RunScript(
                                scriptName,
                                scriptType,
                                List.of(
                                        new RunStep(
                                                -1,
                                                "",
                                                List.of(
                                                        new StepOutput(
                                                                0,
                                                                OUTPUT_KIND_ERROR,
                                                                outputDetailMessage)),
                                                screenshotBase64)))));
    }

    private static void attachScreenshot(ScriptsRunStep step, String screenshotBase64) {
        if (StringUtils.isBlank(screenshotBase64)) {
            return;
        }
        ScriptsRunStepScreenshot screenshot = new ScriptsRunStepScreenshot();
        screenshot.setRunStep(step);
        screenshot.setCreateTimestamp(Instant.now());
        screenshot.setData(screenshotBase64);
        step.setScreenshot(screenshot);
    }
}
