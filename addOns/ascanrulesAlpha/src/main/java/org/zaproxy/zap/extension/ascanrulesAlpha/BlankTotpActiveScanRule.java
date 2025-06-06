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

public class BlankTotpActiveScanRule extends AbstractHostPlugin
        implements CommonActiveScanRuleInfo {
    private static final String MESSAGE_PREFIX = "ascanalpha.blanktotp.";
    private static final Logger LOGGER = LogManager.getLogger(BlankTotpActiveScanRule.class);
    private static final Map<String, String> ALERT_TAGS = new HashMap<>();

    @Override
    public int getId() {
        return 40048;
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
        return Category.MISC;
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

            List<AuthenticationStep> mutableAuthSteps = new ArrayList<>(context.authSteps);

            AuthenticationStep testStep = new AuthenticationStep();
            testStep.setType(AuthenticationStep.Type.CUSTOM_FIELD);
            testStep.setXpath(context.totpStep.getXpath());
            testStep.setCssSelector(context.totpStep.getCssSelector());
            testStep.setValue("");

            for (int i = 0; i < mutableAuthSteps.size(); i++) {
                AuthenticationStep step = mutableAuthSteps.get(i);
                if (step.getType() == AuthenticationStep.Type.TOTP_FIELD) {
                    mutableAuthSteps.set(i, testStep); // Replace the TOTP step with the test step
                    break;
                }
            }
            context.browserAuthMethod.setAuthenticationSteps(mutableAuthSteps);
            context.browserAuthMethod.authenticate(
                    context.sessionManagementMethod, context.credentials, context.user);
            boolean webSessionBlankCode = context.browserAuthMethod.wasAuthTestSucessful();

            if (webSessionBlankCode) {
                buildAlert(
                                "Blank Passcode Vulnerability",
                                "The application allows authentication with a blank or empty passcode, which poses a significant security risk. Attackers can exploit this vulnerability to gain unauthorized access without providing valid credentials.",
                                "Enforce strict password policies that require non-empty, strong passcodes. Implement validation checks to prevent blank passcodes during authentication",
                                msg)
                        .raise();
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
