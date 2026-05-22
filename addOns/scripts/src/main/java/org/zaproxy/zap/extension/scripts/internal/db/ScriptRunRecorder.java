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

    /** One output line attached to a run step. */
    public record StepOutput(String kind, String message) {}

    /**
     * One step in a recorded script run. {@code sourceStepIndex} and {@code line} identify the
     * failing statement when present; print output uses {@code -1} and an empty line.
     */
    public record RunStep(
            int sourceStepIndex, String line, List<StepOutput> outputs, String screenshotBase64) {
        public RunStep {
            outputs = outputs == null ? List.of() : List.copyOf(outputs);
        }
    }

    /** One script row in a recorded run, in chain order. */
    public record RunScript(String scriptName, String scriptType, List<RunStep> steps) {
        public RunScript {
            steps = steps == null ? List.of() : List.copyOf(steps);
        }
    }

    private ScriptRunRecorder() {}

    /** Persists the given run; callers decide whether a run is worth recording. */
    public static void recordRun(String summary, String outcome, List<RunScript> scripts) {
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
                    for (RunStep runStep : runScript.steps()) {
                        ScriptsRunStep st = new ScriptsRunStep();
                        st.setRunScript(row);
                        st.setOrdinal(stepOrdinal++);
                        st.setSourceStepIndex(runStep.sourceStepIndex());
                        st.setLine(StringUtils.defaultString(runStep.line()));
                        row.getSteps().add(st);

                        int outputOrdinal = 0;
                        for (StepOutput stepOutput : runStep.outputs()) {
                            ScriptsRunOutput out = new ScriptsRunOutput();
                            out.setRunStep(st);
                            out.setOrdinal(outputOrdinal++);
                            out.setKind(StringUtils.defaultString(stepOutput.kind()));
                            out.setMessage(StringUtils.defaultString(stepOutput.message()));
                            st.getOutputs().add(out);
                        }

                        attachScreenshot(st, runStep.screenshotBase64());
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
