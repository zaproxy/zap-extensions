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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractHostPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.authhelper.internal.AuthenticationStep;

public class TotpActiveScanRule extends AbstractHostPlugin implements CommonActiveScanRuleInfo {
    private static final String MESSAGE_PREFIX = "ascanalpha.commtotp.";
    private static final Logger LOGGER = LogManager.getLogger(TotpActiveScanRule.class);
    private static final Map<String, String> ALERT_TAGS = new HashMap<>();

    @Override
    public int getId() {
        return 40050;
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
        return "N/A";
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

            // Checks if a valid username/password combination gives access with any passcode
            // meeting the format
            // Uses known static backup passcodes to check if any of them work
            List<String> backupPasscodes =
                    List.of(
                            "000000",
                            "0000000",
                            "00000000",
                            "123456",
                            "1234567",
                            "12345678",
                            "888888",
                            "8888888",
                            "88888888");
            // Test passcodes (check format- RFC-6238 (6,7,8)

            for (String code : backupPasscodes) {
                List<AuthenticationStep> testSteps = new ArrayList<>();
                for (AuthenticationStep step : context.authSteps) {
                    if (step.getType() == AuthenticationStep.Type.TOTP_FIELD) {
                        AuthenticationStep clone = new AuthenticationStep(step);
                        clone.setUserProvidedTotp(code); 
                        testSteps.add(clone);
                    } else {
                        testSteps.add(step);
                    }
                }

                context.browserAuthMethod.setAuthenticationSteps(testSteps);
                context.browserAuthMethod.authenticate(
                        context.sessionManagementMethod, context.credentials, context.user);
                boolean webSessionNew = context.browserAuthMethod.wasAuthTestSucessful();

                if (webSessionNew) {
                    buildAlert(
                                    "Passcode Authentication Bypass",
                                    "The application allows authentication using passcodes that meet the expected format but are weak or known values. This poses a security risk as attackers could exploit predictable static backup passcodes to gain unauthorized access.",
                                    "",
                                    msg)
                            .raise();
                    return;
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
