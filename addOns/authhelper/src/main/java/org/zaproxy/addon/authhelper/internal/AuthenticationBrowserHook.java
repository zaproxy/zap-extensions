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
package org.zaproxy.addon.authhelper.internal;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.addon.authhelper.ClientScriptBasedAuthenticationMethodType.ClientScriptBasedAuthenticationMethod;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.extension.selenium.BrowserHook;
import org.zaproxy.zap.extension.selenium.SeleniumScriptUtils;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.users.User;

public class AuthenticationBrowserHook implements BrowserHook {

    private static final Logger LOGGER = LogManager.getLogger(AuthenticationBrowserHook.class);

    private ClientScriptBasedAuthenticationMethod csaMethod;
    private final User user;

    public AuthenticationBrowserHook(Context context, User user) {
        AuthenticationMethod method = context.getAuthenticationMethod();
        if (!(method instanceof ClientScriptBasedAuthenticationMethod)) {
            throw new IllegalStateException("Unsupported method " + method.getType().getName());
        }
        csaMethod = (ClientScriptBasedAuthenticationMethod) method;
        this.user = user;
    }

    @Override
    public void browserLaunched(SeleniumScriptUtils ssUtils) {
        try {
            csaMethod.authenticate(ssUtils.getWebDriver(), user);
        } catch (Exception e) {
            LOGGER.warn(
                    "An error occurred while trying to execute the Client Script Authentication script: {}",
                    e.getMessage());
        }
    }
}
