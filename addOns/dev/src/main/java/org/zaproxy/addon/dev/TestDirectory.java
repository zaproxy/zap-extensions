/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.dev;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.network.server.HttpMessageHandler;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

public class TestDirectory implements HttpMessageHandler {

    private static final Logger LOGGER = LogManager.getLogger(TestDirectory.class);

    public static final String INDEX_PAGE = "index.html";

    private String name;
    private TestProxyServer server;
    private TestDirectory parent;
    private Map<String, TestDirectory> subDirs = new HashMap<>();
    private Map<String, TestPage> pages = new HashMap<>();

    public TestDirectory(TestProxyServer server, String name) {
        this.server = server;
        this.name = name;
    }

    public String getName() {
        return this.name;
    }

    public TestProxyServer getServer() {
        return this.server;
    }

    public TestDirectory getParent() {
        return parent;
    }

    public void setParent(TestDirectory parent) {
        this.parent = parent;
    }

    public String getHierarchicName() {
        if (parent == null) {
            return name;
        }
        return parent.getHierarchicName() + "/" + name;
    }

    public String getPageName(HttpMessage msg) {
        String name = msg.getRequestHeader().getURI().getEscapedName();
        if (name.length() == 0) {
            name = INDEX_PAGE;
        }
        int qIndex = name.indexOf('?');
        if (qIndex > 0) {
            name = name.substring(0, qIndex - 1);
        }
        return name;
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
        LOGGER.debug(
                "handleMessage {} {}",
                msg.getRequestHeader().getMethod(),
                msg.getRequestHeader().getURI());

        String name = getPageName(msg);
        boolean isIndex = INDEX_PAGE.equals(name);

        try {
            TestPage page = getPage(name);
            if (page != null) {
                page.handleMessage(ctx, msg);
                return;
            }

            String body = server.getTextFile(this, name);
            if (body == null && isIndex) {
                body = server.getTextFile(name);
            }

            if (body == null) {
                LOGGER.debug("Failed to find tutorial file {}", name);
                body = server.getTextFile("404.html");
                msg.setResponseBody(body);
                msg.setResponseHeader(
                        TestProxyServer.getDefaultResponseHeader(
                                TestProxyServer.STATUS_NOT_FOUND,
                                "text/html",
                                msg.getResponseBody().length()));
            } else {
                if (isIndex) {
                    StringBuilder sb = new StringBuilder();
                    sb.append("<ul>\n");
                    if (!getName().isEmpty()) {
                        sb.append("<li><a href=\"..\">..</a>\n");
                    }
                    (new TreeSet<>(getSubDirectoryNames()))
                            .forEach(
                                    d -> {
                                        sb.append("<li><a href=\"");
                                        sb.append(d);
                                        sb.append("/\">");
                                        sb.append(d);
                                        sb.append("</a>\n");
                                    });

                    sb.append("</ul>\n");
                    body = body.replace("<!-- SUBDIRS -->", sb.toString());
                }

                msg.setResponseBody(body);
                String contentType = "text/plain"; // Fallback
                if (name.endsWith(".html")) {
                    contentType = "text/html";
                } else if (name.endsWith(".css")) {
                    contentType = "text/css";
                } else if (name.endsWith(".js")) {
                    contentType = "text/javascript";
                } else if (name.endsWith(".json")) {
                    contentType = "application/json";
                } else if (name.endsWith(".yaml")) {
                    contentType = "application/yaml";
                } else {
                    LOGGER.error("Unexpected tutorial file extension: {}", name);
                }
                msg.setResponseHeader(
                        TestProxyServer.getDefaultResponseHeader(
                                contentType, msg.getResponseBody().length()));
            }
        } catch (HttpMalformedHeaderException e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    public void addDirectory(TestDirectory td) {
        this.subDirs.put(td.getName(), td);
        td.setParent(this);
    }

    public TestDirectory getSubDir(String name) {
        return this.subDirs.get(name);
    }

    public Set<String> getSubDirectoryNames() {
        return this.subDirs.keySet();
    }

    public void addPage(TestPage page) {
        this.pages.put(page.getName(), page);
        page.setParent(this);
    }

    public TestPage getPage(String name) {
        return this.pages.get(name);
    }
}
