/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.zap.extension.scripts.automation;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.extension.script.ScriptOutputListener;
import org.zaproxy.zap.extension.script.ScriptWrapper;

public class ScriptJobOutputListener implements ScriptOutputListener {
    private final AutomationProgress progress;
    private final Map<String, StringBuilder> buffers = new HashMap<>();

    public ScriptJobOutputListener(AutomationProgress progress) {
        this.progress = progress;
    }

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

    private void flushLines(String scriptName) {
        StringBuilder buffer = buffers.get(scriptName);
        if (buffer == null) {
            return;
        }
        int index = buffer.indexOf("\n");
        while (index > -1) {
            String line = buffer.substring(0, index);
            if (View.isInitialised()) {
                progress.info(line);
            } else {
                progress.infoNoStdout(line);
            }
            buffer.delete(0, index + 1);
            index = buffer.indexOf("\n");
        }
    }
}
