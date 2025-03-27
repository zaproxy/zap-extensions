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
package org.zaproxy.addon.dev.csrf.basic;

import java.util.TreeSet;
import java.util.UUID;
import java.util.stream.IntStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.dev.TestDirectory;
import org.zaproxy.addon.dev.TestPage;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

public class BasicCsrfDir extends TestDirectory {

    private static final Logger LOGGER = LogManager.getLogger(BasicCsrfDir.class);

    private static final int WIDTH = 10;
    private static final int DEPTH = 10;
    private static final int FIELDS = 5;
    private static final int POST_DELAY_IN_MS = 5;

    private static final String ROW =
            "<tr><td>Field %d</td><td><input name=\"field%d\"></td></tr>\n";

    public BasicCsrfDir(TestProxyServer server, String name) {
        super(server, name);
        IntStream.range(0, WIDTH)
                .forEach(i -> addDirectory(new BasicCsrfSubDir(this, Integer.toString(i), DEPTH)));
    }

    class BasicCsrfSubDir extends TestDirectory {

        private BasicCsrfPage page;

        public BasicCsrfSubDir(TestDirectory parent, String name, int subDirs) {
            super(parent.getServer(), name);
            this.setParent(parent);
            IntStream.range(0, subDirs)
                    .forEach(i -> addDirectory(new BasicCsrfSubDir(this, Integer.toString(i), 0)));
            if (subDirs == 0) {
                page = new BasicCsrfPage(this, name);
            }
        }

        @Override
        public TestPage getPage(String name) {
            return page;
        }
    }

    class BasicCsrfPage extends TestPage {

        private String csrfToken;

        public BasicCsrfPage(TestDirectory parent, String name) {
            super(parent.getServer(), name);
            this.setParent(parent);
        }

        private boolean hasValidToken(TreeSet<HtmlParameter> params) {
            return params.stream()
                    .filter(p -> p.getName().equals("csrf_token"))
                    .allMatch(p -> p.getValue().equals(csrfToken));
        }

        private String getDirFile(String filename) {
            return this.getServer().getTextFile(this.getParent().getParent().getParent(), filename);
        }

        @Override
        public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
            LOGGER.debug("Handle URL {}", msg.getRequestHeader().getURI());

            try {
                switch (msg.getRequestHeader().getMethod()) {
                    case HttpRequestHeader.GET:
                        LOGGER.debug("GET, so ok");
                        break;
                    case HttpRequestHeader.POST:
                        if (!hasValidToken(msg.getFormParams())) {
                            LOGGER.debug("POST with missing or invalid token");
                            msg.setResponseBody(getDirFile("bad-token.html"));
                            msg.setResponseHeader(
                                    TestProxyServer.getDefaultResponseHeader(
                                            "403 Forbidden",
                                            "text/html",
                                            msg.getResponseBody().length()));
                            return;
                        }
                        LOGGER.debug("POST with valid token");
                        Thread.sleep(POST_DELAY_IN_MS);
                        break;
                    default:
                        LOGGER.debug("Unsupported method {}", msg.getRequestHeader().getMethod());
                        msg.setResponseBody(getDirFile("bad-method.html"));
                        msg.setResponseHeader(
                                TestProxyServer.getDefaultResponseHeader(
                                        "405 Method Not Allowed",
                                        "text/html",
                                        msg.getResponseBody().length()));
                        return;
                }

                String body = getDirFile("page.html");

                StringBuilder sb = new StringBuilder();
                IntStream.range(0, FIELDS).forEach(i -> sb.append(String.format(ROW, i, i)));

                csrfToken = UUID.randomUUID().toString();
                LOGGER.debug("Generating new CSRF token {}", csrfToken);

                body =
                        body.replace("<!-- TABLE -->", sb.toString())
                                .replace("<!-- CSRF -->", csrfToken);

                msg.setResponseBody(body);
                msg.setResponseHeader(
                        TestProxyServer.getDefaultResponseHeader(
                                "text/html", msg.getResponseBody().length()));
            } catch (HttpMalformedHeaderException e) {
                LOGGER.error(e.getMessage(), e);
            } catch (InterruptedException e) {
                // Ignore
            }
        }
    }
}
