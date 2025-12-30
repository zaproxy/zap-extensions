/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.zap.extension.llmheader;

import java.util.List;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.alert.ExtensionAlert;

public class AlertBuilder {

    private static final int PLUGIN_ID = 900501;

    public static void buildAlerts(
            ExtensionAlert extAlert, HttpMessage msg, List<LLMIssue> issues) {
        System.out.println("DEBUG: AlertBuilder.buildAlerts called with " + issues.size() + " issues.");
        if (extAlert == null)
            return;

        for (LLMIssue issue : issues) {
            Alert alert = new Alert(
                    PLUGIN_ID,
                    getRisk(issue.getSeverity()),
                    Alert.CONFIDENCE_LOW,
                    "[LLM] Header Issue: " + issue.getIssue());
            alert.setDetail(
                    issue.getIssue(),
                    msg.getRequestHeader().toString(), // URL
                    issue.getIssue(), // Param
                    "", // Attack
                    "", // Other info
                    issue.getRecommendation(), // Solution
                    "", // Reference
                    issue.getIssue(), // Evidence
                    200, // CWE (Information Exposure) - generic
                    13, // WASC (Information Leakage) - generic
                    msg);
            extAlert.alertFound(alert, msg.getHistoryRef());
        }
    }

    private static int getRisk(String severity) {
        if (severity == null)
            return Alert.RISK_LOW;
        switch (severity.toLowerCase()) {
            case "high":
                return Alert.RISK_HIGH;
            case "medium":
                return Alert.RISK_MEDIUM;
            case "low":
                return Alert.RISK_LOW;
            default:
                return Alert.RISK_INFO;
        }
    }
}
