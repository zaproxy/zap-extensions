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

import java.util.UUID;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.dev.TestAuthDirectory;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

/**
 * A login page which uses one JSON request to login endpoint. The token is returned in a standard
 * field but is submitted with the "Bearer" prefix and in a cookie.
 */
public class SimpleJsonCookieDynamicPageDir extends TestAuthDirectory {

    private static final Logger LOGGER = LogManager.getLogger(SimpleJsonCookieDynamicPageDir.class);

    private static String uuid = UUID.randomUUID().toString();

    public SimpleJsonCookieDynamicPageDir(TestProxyServer server, String name) {
        super(server, name);
        //        this.addPage(new SimpleJsonCookieDynamicPageIndexPage(server)); // Unused
        this.addPage(new SimpleJsonCookieProtectedPage(server, "page1.html")); // Unused so far
        this.addPage(
                new SimpleJsonCookieDynamicPageLoginPage(
                        server, SimpleJsonCookieDynamicPageDir.getUuid()));
        this.addPage(new SimpleJsonCookieDynamicPageLoginPage(server));
        this.addPage(new SimpleJsonCookieDynamicPageVerificationPage(server)); // Unused so far
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
        String body = getServer().getTextFile(this, "index.html");
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

    public static String getUuid() {
        return uuid;
    }

    public static void refreshUuid() {
        uuid = UUID.randomUUID().toString();
    }
}
