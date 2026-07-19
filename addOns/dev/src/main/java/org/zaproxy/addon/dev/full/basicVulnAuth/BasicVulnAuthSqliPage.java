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
 * A search page that simulates SQL injection: a single-quote in the 'search' parameter triggers a
 * MySQL-style error (intentionally vulnerable).
 */
public class BasicVulnAuthSqliPage extends BasicVulnAuthProtectedPage {

    private static final Logger LOGGER = LogManager.getLogger(BasicVulnAuthSqliPage.class);

    public BasicVulnAuthSqliPage(TestProxyServer server) {
        super(server, "sqli");
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
        if (getAuthenticatedUser(msg) == null) {
            DevUtils.setRedirect(msg, "index.html");
            return;
        }

        String search = DevUtils.getUrlParam(msg, "search");
        String result = "";
        if (search != null) {
            if (search.contains("'")) {
                // Intentionally vulnerable: simulates a MySQL error on SQL injection probe
                result =
                        "<p>Error: You have an error in your SQL syntax; check the manual that"
                                + " corresponds to your MySQL server version for the right syntax"
                                + " to use near '"
                                + search
                                + "' at line 1</p>";
            } else {
                result =
                        "<p>Search results for: "
                                + search
                                + "</p><ul><li>Result 1</li><li>Result 2</li></ul>";
            }
        }

        String body = getServer().getTextFile(getParent(), "sqli.html");
        body = body.replace("<!-- VALUE -->", search != null ? search : "");
        body = body.replace("<!-- RESULT -->", result);

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
