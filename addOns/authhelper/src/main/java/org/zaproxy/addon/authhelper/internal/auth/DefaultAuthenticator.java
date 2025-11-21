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
package org.zaproxy.addon.authhelper.internal.auth;

import java.util.Iterator;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.authhelper.AuthUtils;
import org.zaproxy.addon.authhelper.AuthenticationDiagnostics;
import org.zaproxy.addon.authhelper.internal.AuthenticationStep;
import org.zaproxy.zap.authentication.UsernamePasswordAuthenticationCredentials;
import org.zaproxy.zap.model.Context;

public class DefaultAuthenticator implements Authenticator {

    private static final Logger LOGGER = LogManager.getLogger(DefaultAuthenticator.class);

    @Override
    public boolean isOwnSite(HttpMessage msg) {
        // Default does not own any site.
        return false;
    }

    @Override
    public Result authenticate(
            AuthenticationDiagnostics diags,
            WebDriver wd,
            Context context,
            String loginPageUrl,
            UsernamePasswordAuthenticationCredentials credentials,
            int stepDelayInSecs,
            int waitInSecs,
            List<AuthenticationStep> steps) {

        String username = credentials.getUsername();
        String password = credentials.getPassword();

        WebElement userField = null;
        WebElement pwdField = null;
        boolean userAdded = false;
        boolean pwdAdded = false;

        Iterator<AuthenticationStep> it = steps.stream().sorted().iterator();
        while (it.hasNext()) {
            AuthenticationStep step = it.next();
            if (!step.isEnabled()) {
                continue;
            }

            if (step.getType() == AuthenticationStep.Type.AUTO_STEPS) {
                break;
            }

            WebElement element = step.execute(wd, credentials);
            diags.recordStep(wd, step.getDescription(), element);

            switch (step.getType()) {
                case USERNAME:
                    userField = element;
                    userAdded = true;
                    break;

                case PASSWORD:
                    pwdField = element;
                    pwdAdded = true;
                    break;

                default:
            }

            AuthUtils.sleepMax(
                    TimeUnit.SECONDS.toMillis(stepDelayInSecs), AuthUtils.TIME_TO_SLEEP_IN_MSECS);
        }

        for (int i = 0; i < AuthUtils.getWaitLoopCount(); i++) {
            if ((userField != null || userAdded) && pwdField != null) {
                break;
            }

            List<WebElement> inputElements = AuthUtils.getInputElements(wd, i > 2);
            pwdField = AuthUtils.getPasswordField(inputElements);
            userField = AuthUtils.getUserField(wd, inputElements, pwdField);

            if (i > 1 && userField != null && pwdField == null && !userAdded) {
                // Handle pages which require you to submit the username first
                LOGGER.debug("Submitting just user field on {}", loginPageUrl);
                AuthUtils.fillUserName(diags, wd, username, userField, stepDelayInSecs);
                AuthUtils.sendReturnAndSleep(diags, wd, userField, stepDelayInSecs);
                userAdded = true;
            }
            AuthUtils.sleep(AuthUtils.TIME_TO_SLEEP_IN_MSECS);
        }

        boolean successful = false;
        if ((userField != null || userAdded) && pwdField != null) {
            if (!userAdded) {
                LOGGER.debug("Entering user field on {}", wd.getCurrentUrl());
                AuthUtils.fillUserName(diags, wd, username, userField, stepDelayInSecs);
            }
            try {
                if (!pwdAdded) {
                    LOGGER.debug("Submitting password field on {}", wd.getCurrentUrl());
                    AuthUtils.fillPassword(diags, wd, password, pwdField, stepDelayInSecs);
                }
                AuthUtils.submit(diags, wd, pwdField, stepDelayInSecs, waitInSecs);
            } catch (Exception e) {
                diags.reportFlowException(e);

                if (userField != null) {
                    // Handle the case where the password field was present but hidden / disabled
                    LOGGER.debug("Handling hidden password field on {}", wd.getCurrentUrl());
                    AuthUtils.sendReturnAndSleep(diags, wd, userField, stepDelayInSecs);
                    AuthUtils.sleep(AuthUtils.TIME_TO_SLEEP_IN_MSECS);
                    AuthUtils.fillPassword(diags, wd, password, pwdField, stepDelayInSecs);
                    AuthUtils.sendReturnAndSleep(diags, wd, pwdField, stepDelayInSecs);
                }
            }

            while (it.hasNext()) {
                AuthenticationStep step = it.next();
                if (!step.isEnabled()) {
                    continue;
                }

                step.execute(wd, credentials);
                diags.recordStep(wd, step.getDescription());

                AuthUtils.sleepMax(
                        TimeUnit.SECONDS.toMillis(stepDelayInSecs),
                        AuthUtils.TIME_TO_SLEEP_IN_MSECS);
            }

            successful = true;
        }

        return new Result(true, successful, userField != null, pwdField != null);
    }
}
