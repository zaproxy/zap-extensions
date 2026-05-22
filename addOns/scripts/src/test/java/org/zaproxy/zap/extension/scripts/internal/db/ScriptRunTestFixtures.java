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

/**
 * JDO entity fixtures for script-run tests. {@link #defaultFailedChainRunWithErrorStep()} mirrors
 * the second run in {@code ReportTestUtils.defaultScriptDiagnosticRuns()} (reports add-on tests).
 */
public final class ScriptRunTestFixtures {

    private ScriptRunTestFixtures() {}

    /** Failed chain run with error step and screenshot (report JSON defaults, run index 1). */
    public static ScriptsRun defaultFailedChainRunWithErrorStep() {
        ScriptsRun run = new ScriptsRun();
        run.setCreateTimestamp(Instant.parse("2026-04-02T08:30:00Z"));
        run.setOutcome(ScriptRunRecorder.OUTCOME_FAILED);
        run.setSummary("Job: ... step failed");

        ScriptsRunScript script = scriptRow(run, 0, "chain-a");
        run.getScripts().add(script);

        ScriptsRunStep errorStep = new ScriptsRunStep();
        errorStep.setRunScript(script);
        errorStep.setOrdinal(0);
        errorStep.setSourceStepIndex(13);
        errorStep.setLine("ZestClientElementClick");

        ScriptsRunOutput errorOutput = new ScriptsRunOutput();
        errorOutput.setRunStep(errorStep);
        errorOutput.setOrdinal(0);
        errorOutput.setKind(ScriptRunRecorder.OUTPUT_KIND_ERROR);
        errorOutput.setMessage("step failed");
        errorStep.getOutputs().add(errorOutput);

        ScriptsRunStepScreenshot screenshot = new ScriptsRunStepScreenshot();
        screenshot.setRunStep(errorStep);
        screenshot.setData("abc64png");
        errorStep.setScreenshot(screenshot);

        script.getSteps().add(errorStep);
        return run;
    }

    static ScriptsRunScript scriptRow(ScriptsRun run, int ordinal, String name) {
        ScriptsRunScript row = new ScriptsRunScript();
        row.setRun(run);
        row.setOrdinal(ordinal);
        row.setScriptName(name);
        row.setScriptType("standalone");
        return row;
    }
}
