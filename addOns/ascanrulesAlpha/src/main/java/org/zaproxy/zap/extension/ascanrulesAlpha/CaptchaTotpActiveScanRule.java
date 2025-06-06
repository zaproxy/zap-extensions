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
import org.zaproxy.addon.authhelper.BrowserBasedAuthenticationMethodType.BrowserBasedAuthenticationMethod;
import org.zaproxy.addon.authhelper.internal.AuthenticationStep;
import org.zaproxy.zap.authentication.UsernamePasswordAuthenticationCredentials;
import org.zaproxy.zap.session.SessionManagementMethod;
import org.zaproxy.zap.session.WebSession;
import org.zaproxy.zap.users.User;

public class CaptchaTotpActiveScanRule extends AbstractHostPlugin
        implements CommonActiveScanRuleInfo {
    private static final String MESSAGE_PREFIX = "ascanalpha.captchatotp.";
    private static final Logger LOGGER = LogManager.getLogger(CaptchaTotpActiveScanRule.class);
    private static final Map<String, String> ALERT_TAGS = new HashMap<>();

    @Override
    public int getId() {
        return 40051;
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

            // Check if lockout or captcha mechanism is detected
            boolean captchaDetected = false;
            boolean lockoutDetected = false;

            // Run 10 incorrect authentications and store the responses
            // Check responses for any changes or any common captcha technology

            List<AuthenticationStep> authSteps = new ArrayList<>(context.authSteps);
            AuthenticationStep totpStep = context.totpStep;
            int totpIndex = authSteps.indexOf(totpStep);
            List<AuthenticationStep> subset =
                    new ArrayList<>(authSteps.subList(totpIndex + 1, authSteps.size()));
            for (int i = 0; i < 9; i++) {
                for (AuthenticationStep step : subset) {
                    authSteps.add(step);
                }
            }
            WebSession test =
                    testAuthenticatSession(
                            context.totpStep,
                            "111111",
                            authSteps,
                            context.browserAuthMethod,
                            context.sessionManagementMethod,
                            context.credentials,
                            context.user);

            List<HttpMessage> messages = context.browserAuthMethod.getRecordedHttpMessages();

            // Check for key captcha words in the responses
            String[] captchaKeywords = {
                "captcha",
                "g-recaptcha",
                "hcaptcha",
                "data-sitekey",
                "verify you are human",
                "challenge-response",
                "bot detection",
                "recaptcha/api.js",
                "hcaptcha.com/1/api.js",
                "please solve the captcha",
                "captcha verification",
                "input type=\"hidden\" name=\"g-recaptcha-response\""
            };
            for (String keyword : captchaKeywords) {
                for (HttpMessage response : messages) {
                    String contentType = response.getResponseHeader().getHeader("Content-Type");
                    if (contentType == null || !contentType.toLowerCase().contains("text")) {
                        continue;
                    }
                    if (response.getResponseBody().toString().toLowerCase().contains(keyword)) {
                        captchaDetected = true;
                        return;
                    }
                }
            }

            // Check for lockout words in the responses
            String[] lockoutKeywords = {
                "lockout",
                "locked",
                "too many failed attempts",
                "too many login attempts",
                "reset your password",
                "account disabled",
                "unlock"
            };
            for (String keyword : lockoutKeywords) {
                for (HttpMessage response : messages) {
                    String contentType = response.getResponseHeader().getHeader("Content-Type");
                    if (contentType == null || !contentType.toLowerCase().contains("text")) {
                        continue;
                    }
                    if (response.getResponseBody().toString().toLowerCase().contains(keyword)) {
                        lockoutDetected = true;
                        return;
                    } else if (response.getResponseHeader().getStatusCode() == 403) {
                        lockoutDetected = true;
                        return;
                    }
                }
            }

            if (!captchaDetected && !lockoutDetected) {
                buildAlert(
                                "No Lockout or Captcha Mechanism Detected",
                                "\"The application does not enforce CAPTCHA or account lockout mechanisms, making it vulnerable to brute-force attacks.",
                                "Implement CAPTCHA verification and/or account lockout policies after multiple failed login attempts.",
                                msg)
                        .raise();
            }
        } catch (Exception e) {
            LOGGER.error("Error in TOTP Page Scan Rule: {}", e.getMessage(), e);
        }
    }

    private WebSession testAuthenticatSession(
            AuthenticationStep totpStep,
            String newTotpValue,
            List<AuthenticationStep> authSteps,
            BrowserBasedAuthenticationMethod browserAuthMethod,
            SessionManagementMethod sessionManagementMethod,
            UsernamePasswordAuthenticationCredentials credentials,
            User user) {
        if (totpStep.getType() == AuthenticationStep.Type.TOTP_FIELD)
            totpStep.setUserProvidedTotp(newTotpValue);
        else totpStep.setValue(newTotpValue);
        browserAuthMethod.setAuthenticationSteps(authSteps);
        return browserAuthMethod.authenticate(sessionManagementMethod, credentials, user);
    }

    private AlertBuilder buildAlert(
            String name, String description, String solution, HttpMessage msg) {
        return newAlert()
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setName(name)
                .setDescription(description)
                .setSolution(solution)
                .setMessage(msg);
    }
}
