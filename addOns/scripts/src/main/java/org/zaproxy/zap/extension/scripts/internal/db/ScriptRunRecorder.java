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

/** Persists failed script runs; persistence errors are logged and not rethrown. */
public final class ScriptRunRecorder {

    private static final Logger LOGGER = LogManager.getLogger(ScriptRunRecorder.class);

    public static final String OUTCOME_FAILED = "FAILED";
    public static final String OUTPUT_KIND_ERROR = "ERROR";

    /**
     * One script row in a recorded run, in chain order. {@link #failure()} is set on the script
     * that owns the failure step, if any.
     */
    public record RunScript(String scriptName, String scriptType, FailureStep failure) {}

    /**
     * {@code sourceStepIndex}: statement index in the failing script, or {@code -1}. {@code line}:
     * failing element type name.
     */
    public record FailureStep(int sourceStepIndex, String line) {}

    private ScriptRunRecorder() {}

    /** Persists one failed run; {@code scripts} must be non-empty and in chain order. */
    public static void recordFailedRun(
            String summary, List<RunScript> scripts, String outputDetailMessage) {
        String summaryToStore = StringUtils.defaultString(summary);
        String outputToStore = StringUtils.defaultString(outputDetailMessage);
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
            run.setOutcome(OUTCOME_FAILED);
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

                    FailureStep failure = runScript.failure();
                    if (failure == null) {
                        continue;
                    }

                    ScriptsRunStep st = new ScriptsRunStep();
                    st.setRunScript(row);
                    st.setOrdinal(0);
                    st.setSourceStepIndex(failure.sourceStepIndex());
                    st.setLine(StringUtils.defaultString(failure.line()));
                    row.getSteps().add(st);

                    ScriptsRunOutput out = new ScriptsRunOutput();
                    out.setRunStep(st);
                    out.setOrdinal(0);
                    out.setKind(OUTPUT_KIND_ERROR);
                    out.setMessage(
                            StringUtils.isNotBlank(outputToStore) ? outputToStore : summaryToStore);
                    st.getOutputs().add(out);
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
            String outputDetailMessage) {
        recordFailedRun(
                summaryMessage,
                List.of(new RunScript(scriptName, scriptType, new FailureStep(-1, ""))),
                outputDetailMessage);
    }
}
