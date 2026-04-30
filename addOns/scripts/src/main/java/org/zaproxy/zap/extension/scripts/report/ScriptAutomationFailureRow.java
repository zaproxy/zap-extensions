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
package org.zaproxy.zap.extension.scripts.report;

import java.util.Objects;

/** Row exposed to report templates for persisted automation script job failures. */
public final class ScriptAutomationFailureRow {

    private final String scriptName;
    private final String scriptType;
    private final String message;
    private final String createTimestamp;

    public ScriptAutomationFailureRow(
            String scriptName, String scriptType, String message, String createTimestamp) {
        this.scriptName = Objects.requireNonNullElse(scriptName, "");
        this.scriptType = Objects.requireNonNullElse(scriptType, "");
        this.message = Objects.requireNonNullElse(message, "");
        this.createTimestamp = Objects.requireNonNullElse(createTimestamp, "");
    }

    public String getScriptName() {
        return scriptName;
    }

    public String getScriptType() {
        return scriptType;
    }

    public String getMessage() {
        return message;
    }

    public String getCreateTimestamp() {
        return createTimestamp;
    }
}
