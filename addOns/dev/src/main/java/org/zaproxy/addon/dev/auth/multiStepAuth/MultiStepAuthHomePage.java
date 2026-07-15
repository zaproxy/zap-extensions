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
package org.zaproxy.addon.dev.auth.multiStepAuth;

import java.net.HttpCookie;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.dev.DevUtils;
import org.zaproxy.addon.dev.TestPage;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

/** The post-authentication home page, served after a successful login redirect. */
public class MultiStepAuthHomePage extends TestPage {

    private static final Logger LOGGER = LogManager.getLogger(MultiStepAuthHomePage.class);

    public MultiStepAuthHomePage(TestProxyServer server) {
        super(server, "home");
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
        String user = getSessionUser(msg);
        if (user == null) {
            LOGGER.debug("Home page request with no valid session — redirecting to login");
            DevUtils.setRedirect(msg, "index.html");
            return;
        }
        LOGGER.debug("Home page request, user: {}", user);

        String body = this.getServer().getTextFile(this.getParent(), "home.html");
        body = body.replace("<!-- USER -->", user);
        msg.setResponseBody(body);
        try {
            msg.setResponseHeader(
                    TestProxyServer.getDefaultResponseHeader(
                            "text/html", msg.getResponseBody().length()));
        } catch (HttpMalformedHeaderException e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    private String getSessionUser(HttpMessage msg) {
        List<HttpCookie> cookies = msg.getRequestHeader().getHttpCookies();
        for (HttpCookie cookie : cookies) {
            if ("session".equals(cookie.getName())) {
                return getParent().getUser(cookie.getValue());
            }
        }
        return null;
    }

    @Override
    public MultiStepAuthDir getParent() {
        return (MultiStepAuthDir) super.getParent();
    }
}
