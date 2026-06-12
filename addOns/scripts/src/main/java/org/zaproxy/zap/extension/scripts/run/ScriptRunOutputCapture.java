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
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.commons.lang3.StringUtils;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptOutputListener;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.scripts.internal.db.ScriptRunRecorder;
import org.zaproxy.zap.extension.scripts.internal.db.ScriptRunRecorder.RunScript;
import org.zaproxy.zap.extension.scripts.internal.db.ScriptRunRecorder.RunStep;
import org.zaproxy.zap.extension.scripts.internal.db.ScriptRunRecorder.StepOutput;

/** Captures script output lines for persistence; not used for automation progress. */
public class ScriptRunOutputCapture implements ScriptOutputListener {

    private final Map<String, StringBuilder> buffers = new HashMap<>();
    private final Map<String, List<String>> capturedLinesByScriptName = new HashMap<>();

    @Override
    public void output(ScriptWrapper script, String output) {
        String scriptName = script.getName();
        buffers.computeIfAbsent(scriptName, k -> new StringBuilder()).append(output);
        flushLines(scriptName);
    }

    public void flush() {
        for (String scriptName : List.copyOf(buffers.keySet())) {
            StringBuilder buffer = buffers.get(scriptName);
            if (buffer != null && buffer.length() > 0) {
                buffer.append("\n");
                flushLines(scriptName);
            }
        }
    }

    public List<RunScript> toRunScripts(ExtensionScript extScript, Set<String> excludeScriptNames) {
        Set<String> excluded = excludeScriptNames == null ? Set.of() : excludeScriptNames;
        List<RunScript> scripts = new ArrayList<>();
        for (Map.Entry<String, List<String>> entry : capturedLinesByScriptName.entrySet()) {
            if (excluded.contains(entry.getKey()) || entry.getValue().isEmpty()) {
                continue;
            }
            scripts.add(toRunScript(extScript, entry.getKey(), entry.getValue()));
        }
        return scripts;
    }

    public RunScript toRunScript(
            ExtensionScript extScript, String scriptName, String scriptType, List<RunStep> steps) {
        return new RunScript(
                StringUtils.defaultString(scriptName),
                StringUtils.defaultString(scriptType),
                steps == null ? List.of() : steps);
    }

    public List<String> getLines(String scriptName) {
        return capturedLinesByScriptName.getOrDefault(scriptName, List.of());
    }

    private RunScript toRunScript(
            ExtensionScript extScript, String scriptName, List<String> lines) {
        ScriptWrapper wrapper = extScript.getScript(scriptName);
        String scriptType = wrapper != null ? StringUtils.defaultString(wrapper.getTypeName()) : "";
        List<RunStep> steps = new ArrayList<>(lines.size());
        for (String line : lines) {
            steps.add(outputStep(line));
        }
        return new RunScript(scriptName, scriptType, steps);
    }

    static RunStep outputStep(String message) {
        return new RunStep(
                -1,
                "",
                List.of(
                        new StepOutput(
                                ScriptRunRecorder.OUTPUT_KIND_OUTPUT,
                                StringUtils.defaultString(message))),
                null);
    }

    static RunStep errorStep(
            int sourceStepIndex, String line, String message, String screenshotBase64) {
        return new RunStep(
                sourceStepIndex,
                StringUtils.defaultString(line),
                List.of(
                        new StepOutput(
                                ScriptRunRecorder.OUTPUT_KIND_ERROR,
                                StringUtils.defaultString(message))),
                screenshotBase64);
    }

    private void flushLines(String scriptName) {
        StringBuilder buffer = buffers.get(scriptName);
        if (buffer == null) {
            return;
        }
        int index = buffer.indexOf("\n");
        while (index > -1) {
            String line = buffer.substring(0, index);
            capturedLinesByScriptName.computeIfAbsent(scriptName, k -> new ArrayList<>()).add(line);
            buffer.delete(0, index + 1);
            index = buffer.indexOf("\n");
        }
    }

    Set<String> capturedScriptNames() {
        return Collections.unmodifiableSet(new HashSet<>(capturedLinesByScriptName.keySet()));
    }
}
