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
package org.zaproxy.zap.extension.ascanrules.sqli.strategies;

import java.io.IOException;
import java.util.List;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.ascanrules.sqli.DetectionStrategy;
import org.zaproxy.zap.extension.ascanrules.sqli.ResponseComparator;
import org.zaproxy.zap.extension.ascanrules.sqli.ScanContext;

public class LoginBypassDetectionStrategy implements DetectionStrategy {

    private static final List<String> LOGIN_KEYWORDS = List.of(
            "login", "password", "username", "user", "pass", "auth");

    private static final List<String> SUCCESS_KEYWORDS = List.of(
            "welcome", "hello", "dashboard", "home", "authenticated", "success");

    private final ResponseComparator comparator = new ResponseComparator();

    @Override
    public boolean detect(ScanContext context) throws IOException {
        String originalValue =
                context.getOriginalValue() == null ? "" : context.getOriginalValue();
        int budget = context.getRemainingBudget();
        if (budget < 4) {
            return false;
        }

        // Baseline
        HttpMessage baseline = context.newMessage();
        context.setParam(baseline, originalValue);
        context.sendAndReceive(baseline);
        String baselineBody = baseline.getResponseBody().toString().toLowerCase();

        // Check if this looks like a login context
        if (!isLoginContext(baselineBody)) {
            return false;
        }

        int used = 1;

        // Try simple boolean bypass: ' OR '1'='1
        String bypassPayload = originalValue + "' OR '1'='1' -- ";
        HttpMessage bypassMsg = context.newMessage();
        context.setParam(bypassMsg, bypassPayload);
        context.sendAndReceive(bypassMsg);
        used++;

        String bypassBody = bypassMsg.getResponseBody().toString().toLowerCase();

        // Check if bypass triggers success keywords
        if (hasSuccessIndicators(bypassBody) && !hasSuccessIndicators(baselineBody)) {
            context.newAlert()
                    .setConfidence(Alert.CONFIDENCE_MEDIUM)
                    .setParam(context.getParamName())
                    .setAttack(bypassPayload)
                    .setOtherInfo("Login bypass via SQL injection detected")
                    .setMessage(bypassMsg)
                    .raise();
            return true;
        }

        return false;
    }

    private boolean isLoginContext(String body) {
        for (String keyword : LOGIN_KEYWORDS) {
            if (body.contains(keyword)) {
                return true;
            }
        }
        return false;
    }

    private boolean hasSuccessIndicators(String body) {
        for (String keyword : SUCCESS_KEYWORDS) {
            if (body.contains(keyword)) {
                return true;
            }
        }
        return false;
    }
}
