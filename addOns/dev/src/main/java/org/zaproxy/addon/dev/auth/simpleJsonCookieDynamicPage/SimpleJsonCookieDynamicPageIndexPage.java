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
package org.zaproxy.addon.dev.auth.simpleJsonCookieDynamicPage;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.dev.TestPage;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

public class SimpleJsonCookieDynamicPageIndexPage extends TestPage {

    private static final Logger LOGGER =
            LogManager.getLogger(SimpleJsonCookieDynamicPageIndexPage.class);

    public SimpleJsonCookieDynamicPageIndexPage(TestProxyServer server) {
        super(server, "index.html");
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
        LOGGER.info(msg.getRequestHeader().getURI().toString());
        String body = getServer().getTextFile("index.html");
        body = body.replace("@@@replace@@@", SimpleJsonCookieDynamicPageDir.getUuid());

        msg.setResponseBody(body);
        try {
            msg.setResponseHeader(
                    TestProxyServer.getDefaultResponseHeader(
                            "200", "text/html", msg.getResponseBody().length()));
        } catch (HttpMalformedHeaderException e) {
            // Ignore
        }
    }

    @Override
    public SimpleJsonCookieDynamicPageDir getParent() {
        return (SimpleJsonCookieDynamicPageDir) super.getParent();
    }
}
