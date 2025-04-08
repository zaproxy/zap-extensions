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
package org.zaproxy.zap.extension.ascanrulesAlpha;

import java.util.HashMap;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractHostPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.authhelper.internal.AuthenticationStep;
import org.zaproxy.zap.session.WebSession;

public class ReplayTotpActiveScanRule extends AbstractHostPlugin
        implements CommonActiveScanRuleInfo {
    private static final String MESSAGE_PREFIX = "ascanalpha.replaytotp.";
    private static final Logger LOGGER = LogManager.getLogger(ReplayTotpActiveScanRule.class);
    private static final Map<String, String> ALERT_TAGS = new HashMap<>();

    @Override
    public int getId() {
        return 40049;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    @Override
    public int getCategory() {
        return Category.INFO_GATHER;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    @Override
    public String getReference() {
        return "N/A";
    }

    @Override
    public void scan() {
        try {

            // Get target URL from request
            HttpMessage msg = getBaseMsg();

            TotpScanContext context = TotpScanContextHelper.resolve(msg);
            if (context == null) {
                return;
            }

            // Check if user provided valid code & check if initial authentication works with normal
            // passcode
            if (context.totpStep.getValue() != null || !context.totpStep.getValue().isEmpty()) {
                if (context.totpStep.getType() == AuthenticationStep.Type.TOTP_FIELD)
                    context.totpStep.setUserProvidedTotp(context.totpStep.getValue());
                WebSession webSession =
                        context.browserAuthMethod.authenticate(
                                context.sessionManagementMethod, context.credentials, context.user);
                if (webSession == null) {
                    // LOGGER.error("Normal Authentication unsuccessful. TOTP not configured
                    // correctly.");
                    return;
                }
                // Check for passcode reuse vulnerability
                WebSession webSession_redo =
                        context.browserAuthMethod.authenticate(
                                context.sessionManagementMethod, context.credentials, context.user);
                if (webSession_redo != null) {
                    LOGGER.error("Authentication with reused passcode. Vulnerability found.");
                    buildAlert(
                                    "TOTP Replay Attack Vulnerability",
                                    "The application is vulnerable to replay attacks, allowing attackers to reuse previously intercepted TOTP codes to authenticate.",
                                    "Ensure that TOTP codes are validated only once per session and are invalidated after use.",
                                    msg)
                            .raise();
                }
            }
        } catch (Exception e) {
            LOGGER.error("Error in TOTP Page Scan Rule: {}", e.getMessage(), e);
        }
    }

    private AlertBuilder buildAlert(
            String name, String description, String solution, HttpMessage msg) {
        return newAlert()
                .setConfidence(Alert.CONFIDENCE_HIGH)
                .setName(name)
                .setDescription(description)
                .setSolution(solution)
                .setMessage(msg);
    }
}
