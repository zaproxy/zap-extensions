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
package org.zaproxy.zap.extension.scripts.automation.diagnostics;

import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.scripts.automation.ScriptJobOutputListener;
import org.zaproxy.zap.extension.scripts.automation.diagnostics.ScriptRunRecordBuilder.RunFailure;
import org.zaproxy.zap.extension.scripts.automation.diagnostics.ScriptRunRecordBuilder.ScriptMember;
import org.zaproxy.zap.extension.scripts.diagnostics.ScriptDiagnosticSource;
import org.zaproxy.zap.extension.scripts.internal.db.ScriptRunRecorder;

/** Runs automation scripts and persists diagnostics. */
public class ScriptRunDiagnosticsSession {

    private static final Logger LOGGER = LogManager.getLogger(ScriptRunDiagnosticsSession.class);

    private final ExtensionScript extensionScript;

    public ScriptRunDiagnosticsSession(ExtensionScript extensionScript) {
        this.extensionScript = extensionScript;
    }

    public record RunContext(
            String jobName,
            String successSummary,
            String failureSummary,
            List<ScriptMember> members) {}

    @FunctionalInterface
    public interface ScriptExecutor {
        void execute() throws Exception;
    }

    public boolean execute(
            ScriptWrapper script,
            AutomationProgress progress,
            ScriptExecutor executor,
            RunContext context,
            FailureReporter failureReporter) {
        ScriptJobOutputListener progressListener =
                new ScriptJobOutputListener(progress, script.getName());
        try {
            extensionScript.addScriptOutputListener(progressListener);
            executor.execute();
            progressListener.flush();

            if (script.getLastException() != null) {
                progressListener.flush();
                failureReporter.reportFailure(script.getLastException());
                return false;
            }
            persistSuccess(script, context);
            return true;
        } catch (Exception e) {
            LOGGER.debug("Script execution failed, reported via automation progress", e);
            progressListener.flush();
            failureReporter.reportFailure(e);
            return false;
        } finally {
            extensionScript.removeScriptOutputListener(progressListener);
        }
    }

    private void persistSuccess(ScriptWrapper script, RunContext context) {
        List<ScriptRunRecorder.RunScript> scripts =
                ScriptRunRecordBuilder.build(context.members(), null, runOutputs(script), "");
        if (scripts.stream().noneMatch(s -> !s.steps().isEmpty())) {
            return;
        }
        ScriptRunRecorder.recordRun(
                ScriptRunRecorder.OUTCOME_SUCCESS, context.successSummary(), scripts);
    }

    public void persistFailure(ScriptWrapper script, RunContext context, RunFailure failure) {
        ScriptRunRecorder.recordFailedRun(
                context.failureSummary(),
                ScriptRunRecordBuilder.build(
                        context.members(), failure, runOutputs(script), failure.outputDetail()));
    }

    private static List<ScriptDiagnosticSource.RunOutput> runOutputs(ScriptWrapper script) {
        if (script instanceof ScriptDiagnosticSource source) {
            return source.getRunDiagnostics().outputs();
        }
        return List.of();
    }

    @FunctionalInterface
    public interface FailureReporter {
        void reportFailure(Exception e);
    }
}
