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

import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.authhelper.BrowserBasedAuthenticationMethodType.BrowserBasedAuthenticationMethod;
import org.zaproxy.addon.authhelper.internal.AuthenticationStep;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.authentication.UsernamePasswordAuthenticationCredentials;
import org.zaproxy.zap.extension.users.ExtensionUserManagement;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.session.SessionManagementMethod;
import org.zaproxy.zap.users.User;

public class TotpScanContextHelper {
    private static final Logger LOGGER = LogManager.getLogger(TotpScanContextHelper.class);

    public static TotpScanContext resolve(HttpMessage msg) {
        try {
            ExtensionUserManagement usersExtension =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionUserManagement.class);
            if (usersExtension == null) {
                return null;
            }

            String targetUrl = msg.getRequestHeader().getURI().toString();
            Session session = Model.getSingleton().getSession();
            Context activeContext = null;
            for (Context context : session.getContexts()) {
                if (context.isInContext(targetUrl)) {
                    activeContext = context;
                    break;
                }
            }
            if (activeContext == null) {
                return null;
            }

            AuthenticationMethod authMethod = activeContext.getAuthenticationMethod();
            if (!(authMethod instanceof BrowserBasedAuthenticationMethod)) {
                return null;
            }

            BrowserBasedAuthenticationMethod browserAuthMethod =
                    (BrowserBasedAuthenticationMethod) authMethod;
            List<AuthenticationStep> authSteps = browserAuthMethod.getAuthenticationSteps();

            AuthenticationStep totpStep = null;
            for (AuthenticationStep step : authSteps) {
                if (step.getType() == AuthenticationStep.Type.TOTP_FIELD
                        || (step.getType() == AuthenticationStep.Type.CUSTOM_FIELD
                                && step.getDescription().toLowerCase().contains("totp"))) {
                    totpStep = step;
                    break;
                }
            }
            if (totpStep == null) {
                return null;
            }

            List<User> users =
                    usersExtension.getContextUserAuthManager(activeContext.getId()).getUsers();
            if (users == null || users.isEmpty()) {
                return null;
            }

            User user = users.get(0);
            UsernamePasswordAuthenticationCredentials credentials =
                    (UsernamePasswordAuthenticationCredentials) user.getAuthenticationCredentials();

            SessionManagementMethod sessionManagementMethod =
                    activeContext.getSessionManagementMethod();

            return new TotpScanContext(
                    activeContext,
                    browserAuthMethod,
                    authSteps,
                    totpStep,
                    credentials,
                    sessionManagementMethod,
                    user);

        } catch (Exception e) {
            LOGGER.error("Error resolving TOTP scan context: {}", e.getMessage(), e);
            return null;
        }
    }
}
