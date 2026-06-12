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
package org.zaproxy.zap.extension.scripts.run;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.apache.commons.lang3.StringUtils;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptOutputListener;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.scripts.automation.ScriptJobOutputListener;
import org.zaproxy.zap.extension.scripts.internal.db.ScriptRunRecorder.RunScript;
import org.zaproxy.zap.extension.scripts.internal.db.ScriptRunRecorder.RunStep;
import org.zaproxy.zap.extension.scripts.zest.ZestScriptDiagnosticSource;

/** Collects script run data during one automation job execution. */
public class ScriptRunSession {

    private final ExtensionScript extScript;
    private final ScriptJobOutputListener progressListener;
    private final ScriptRunOutputCapture outputCapture;

    public ScriptRunSession(ExtensionScript extScript, AutomationProgress progress) {
        this.extScript = extScript;
        this.progressListener = new ScriptJobOutputListener(progress);
        this.outputCapture = new ScriptRunOutputCapture();
    }

    public ScriptOutputListener progressListener() {
        return progressListener;
    }

    public ScriptOutputListener outputCapture() {
        return outputCapture;
    }

    public void flush() {
        progressListener.flush();
        outputCapture.flush();
    }

    public List<RunScript> buildRecord(ScriptWrapper primary) {
        if (primary instanceof ZestScriptDiagnosticSource zest) {
            return zest.getLastRunSnapshot()
                    .map(
                            snapshot -> {
                                Set<String> primaryNames =
                                        snapshot.rows().stream()
                                                .map(r -> r.scriptName())
                                                .collect(Collectors.toCollection(HashSet::new));
                                primaryNames.add(StringUtils.defaultString(primary.getName()));
                                List<RunScript> scripts =
                                        new ArrayList<>(
                                                ScriptRunMapper.fromSnapshot(snapshot, extScript));
                                scripts.addAll(outputCapture.toRunScripts(extScript, primaryNames));
                                return scripts;
                            })
                    .orElseGet(() -> buildNonZestRecord(primary));
        }
        return buildNonZestRecord(primary);
    }

    public List<RunScript> buildRecord(ScriptWrapper primary, Exception e) {
        return ScriptRunFailureResolver.addNonZestFailure(buildRecord(primary), primary, e);
    }

    private List<RunScript> buildNonZestRecord(ScriptWrapper primary) {
        String scriptName = StringUtils.defaultString(primary.getName());
        List<RunStep> steps = new ArrayList<>();
        for (String line : outputCapture.getLines(scriptName)) {
            steps.add(ScriptRunOutputCapture.outputStep(line));
        }
        List<RunScript> scripts = new ArrayList<>();
        if (!steps.isEmpty()) {
            scripts.add(
                    outputCapture.toRunScript(extScript, scriptName, primary.getTypeName(), steps));
        }
        scripts.addAll(outputCapture.toRunScripts(extScript, Set.of(scriptName)));
        return scripts;
    }
}
