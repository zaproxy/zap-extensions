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
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.dev.DevUtils;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

/**
 * Reflects the 'name' URL parameter into the response without encoding (intentionally vulnerable).
 */
public class BasicVulnAuthReflectedXssPage extends BasicVulnAuthProtectedPage {

    private static final Logger LOGGER = LogManager.getLogger(BasicVulnAuthReflectedXssPage.class);

    public BasicVulnAuthReflectedXssPage(TestProxyServer server) {
        super(server, "reflected-xss");
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
        if (getAuthenticatedUser(msg) == null) {
            DevUtils.setRedirect(msg, "index.html");
            return;
        }

        String name = DevUtils.getUrlParam(msg, "name");
        String body = getServer().getTextFile(getParent(), "reflected-xss.html");
        body = body.replace("<!-- VALUE -->", name != null ? name : "");
        // Intentionally vulnerable: name reflected into result without HTML encoding
        body = body.replace("<!-- RESULT -->", name != null ? "<p>Hello, " + name + "!</p>" : "");

        try {
            msg.setResponseBody(body);
            msg.setResponseHeader(
                    TestProxyServer.getDefaultResponseHeader(
                            TestProxyServer.CONTENT_TYPE_HTML_UTF8,
                            msg.getResponseBody().length()));
        } catch (HttpMalformedHeaderException e) {
            LOGGER.error(e.getMessage(), e);
        }
    }
}
