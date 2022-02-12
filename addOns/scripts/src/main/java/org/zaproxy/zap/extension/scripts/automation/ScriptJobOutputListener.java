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

import java.util.Objects;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.extension.script.ScriptOutputListener;
import org.zaproxy.zap.extension.script.ScriptWrapper;

public class ScriptJobOutputListener implements ScriptOutputListener {
    private AutomationProgress progress;
    private String scriptName;
    private StringBuilder stringBuilder;

    public ScriptJobOutputListener(AutomationProgress progress, String scriptName) {
        this.progress = progress;
        this.scriptName = scriptName;
        this.stringBuilder = new StringBuilder();
    }

    @Override
    public void output(ScriptWrapper script, String output) {
        if (Objects.equals(script.getName(), scriptName)) {
            stringBuilder.append(output);
            flushLines();
        }
    }

    public void flush() {
        if (stringBuilder.length() > 0) {
            stringBuilder.append("\n");
            flushLines();
        }
    }

    private void flushLines() {
        int index = nextLineEnd();
        while (index > -1) {
            String line = stringBuilder.substring(0, index);
            progress.info(line);
            stringBuilder.delete(0, index + 1);
            index = nextLineEnd();
        }
    }

    private int nextLineEnd() {
        return stringBuilder.indexOf("\n");
    }
}
