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
package org.zaproxy.addon.authhelper.client;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.WebDriver;
import org.zaproxy.addon.authhelper.AuthUtils;
import org.zaproxy.addon.authhelper.ClientScriptBasedAuthenticationMethodType;
import org.zaproxy.addon.authhelper.ClientScriptBasedAuthenticationMethodType.ClientScriptBasedAuthenticationMethod;
import org.zaproxy.addon.authhelper.internal.ZestAuthRunner;
import org.zaproxy.addon.client.spider.AuthenticationHandler;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.addon.network.server.ServerInfo;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.extension.selenium.BrowserHook;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.extension.selenium.SeleniumScriptUtils;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.users.User;
import org.zaproxy.zest.impl.ZestBasicRunner;

public class ClientScriptBasedAuthHandler implements AuthenticationHandler {

    private static final Logger LOGGER = LogManager.getLogger(ClientScriptBasedAuthHandler.class);

    private BrowserHook browserHook;

    @Override
    public void enableAuthentication(User user) {
        Context context = user.getContext();
        if (context.getAuthenticationMethod()
                instanceof
                ClientScriptBasedAuthenticationMethodType.ClientScriptBasedAuthenticationMethod) {

            if (browserHook != null) {
                throw new IllegalStateException("BrowserHook already enabled");
            }
            browserHook = new AuthenticationBrowserHook(context, user);

            AuthUtils.getExtension(ExtensionSelenium.class).registerBrowserHook(browserHook);
        }
    }

    @Override
    public void disableAuthentication(User user) {
        if (browserHook != null) {
            AuthUtils.getExtension(ExtensionSelenium.class).deregisterBrowserHook(browserHook);
            browserHook = null;
        }
    }

    static class AuthenticationBrowserHook implements BrowserHook {

        private ClientScriptBasedAuthenticationMethod csaMethod;
        private Context context;
        private ZestAuthRunner zestRunner;

        AuthenticationBrowserHook(Context context, User user) {
            this.context = context;
            AuthenticationMethod method = context.getAuthenticationMethod();
            if (!(method instanceof ClientScriptBasedAuthenticationMethod)) {
                throw new IllegalStateException("Unsupported method " + method.getType().getName());
            }
            csaMethod = (ClientScriptBasedAuthenticationMethod) method;
        }

        private ZestBasicRunner getZestRunner(WebDriver webDriver) {
            if (zestRunner == null) {
                zestRunner = new ZestAuthRunner();
                // Always proxy via ZAP
                ServerInfo mainProxyInfo =
                        AuthUtils.getExtension(ExtensionNetwork.class).getMainProxyServerInfo();
                zestRunner.setProxy(mainProxyInfo.getAddress(), mainProxyInfo.getPort());
            }
            zestRunner.setWebDriver(webDriver);
            return zestRunner;
        }

        @Override
        public void browserLaunched(SeleniumScriptUtils ssUtils) {
            ZestBasicRunner runner = getZestRunner(ssUtils.getWebDriver());
            try {
                runner.run(csaMethod.getZestScript(), null);
            } catch (Exception e) {
                LOGGER.warn(
                        "An error occurred while trying to execute the Client Script Authentication script: {}",
                        e.getMessage());
            }
        }
    }
}
