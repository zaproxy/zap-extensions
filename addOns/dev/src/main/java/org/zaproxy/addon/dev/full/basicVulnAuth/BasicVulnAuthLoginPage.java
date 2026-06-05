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
package org.zaproxy.addon.dev.full.basicVulnAuth;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.dev.DevUtils;
import org.zaproxy.addon.dev.TestPage;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

public class BasicVulnAuthLoginPage extends TestPage {

    private static final Logger LOGGER = LogManager.getLogger(BasicVulnAuthLoginPage.class);

    public BasicVulnAuthLoginPage(TestProxyServer server) {
        super(server, "login");
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
        if (!"POST".equalsIgnoreCase(msg.getRequestHeader().getMethod())) {
            DevUtils.setRedirect(msg, "index.html");
            return;
        }

        String username = DevUtils.getFormParam(msg, "username");
        String password = DevUtils.getFormParam(msg, "password");
        LOGGER.debug("Login attempt for user: {}", username);

        if (getParent().isValid(username, password)) {
            String token = getParent().getToken(username);
            DevUtils.setRedirect(msg, "home.html");
            msg.getResponseHeader()
                    .addHeader(HttpHeader.SET_COOKIE, "sid=" + token + "; SameSite=Strict");
        } else {
            DevUtils.setRedirect(msg, "index.html?error=1");
        }
    }

    @Override
    public BasicVulnAuthDir getParent() {
        return (BasicVulnAuthDir) super.getParent();
    }
}
