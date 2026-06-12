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
import java.util.List;
import org.apache.commons.lang3.StringUtils;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.scripts.internal.db.ScriptRunRecorder.RunScript;
import org.zaproxy.zap.extension.scripts.internal.db.ScriptRunRecorder.RunStep;
import org.zaproxy.zap.extension.scripts.zest.ZestScriptDiagnosticSource.ZestScriptRunRow;
import org.zaproxy.zap.extension.scripts.zest.ZestScriptDiagnosticSource.ZestScriptRunSnapshot;

/** Maps Zest run snapshots to persisted run rows. */
public final class ScriptRunMapper {

    private ScriptRunMapper() {}

    public static List<RunScript> fromSnapshot(
            ZestScriptRunSnapshot snapshot, ExtensionScript extScript) {
        List<RunScript> scripts = new ArrayList<>(snapshot.rows().size());
        for (ZestScriptRunRow row : snapshot.rows()) {
            scripts.add(fromRow(row, extScript));
        }
        return scripts;
    }

    private static RunScript fromRow(ZestScriptRunRow row, ExtensionScript extScript) {
        List<RunStep> steps = new ArrayList<>();
        for (String line : row.outputLines()) {
            steps.add(ScriptRunOutputCapture.outputStep(line));
        }
        row.failure()
                .ifPresent(
                        failure ->
                                steps.add(
                                        ScriptRunOutputCapture.errorStep(
                                                failure.sourceStepIndex(),
                                                failure.elementType(),
                                                failure.errorMessage(),
                                                failure.screenshotBase64())));
        ScriptWrapper wrapper = extScript.getScript(row.scriptName());
        String scriptType = wrapper != null ? StringUtils.defaultString(wrapper.getTypeName()) : "";
        return new RunScript(row.scriptName(), scriptType, steps);
    }
}
