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
package org.zaproxy.zap.extension.scripts.automation;

import org.apache.commons.lang3.StringUtils;
import org.zaproxy.zap.extension.scripts.internal.db.ScriptFailureRecorder;

/**
 * Bridges automation job parameters (automation add-on classpath) to {@link ScriptFailureRecorder}
 * (session DB), so {@code internal.db} does not reference {@link
 * org.zaproxy.addon.automation.AutomationData}.
 */
public final class ScriptAutomationFailureRecords {

    private ScriptAutomationFailureRecords() {}

    public static void recordFromParameters(ScriptJobParameters params, String message) {
        if (params == null) {
            ScriptFailureRecorder.record("", "", message);
        } else {
            ScriptFailureRecorder.record(
                    StringUtils.defaultString(params.getName()),
                    StringUtils.defaultString(params.getType()),
                    message);
        }
    }
}
