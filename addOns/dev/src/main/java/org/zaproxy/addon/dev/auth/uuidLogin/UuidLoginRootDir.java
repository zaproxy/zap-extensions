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
package org.zaproxy.addon.dev.auth.uuidLogin;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.dev.DevHttpSenderListener;
import org.zaproxy.addon.dev.DevUtils;
import org.zaproxy.addon.dev.TestAuthDirectory;
import org.zaproxy.addon.dev.TestDirectory;
import org.zaproxy.addon.dev.TestProxyServer;

/**
 * A test app which uses multiple domains:
 *
 * <ul>
 *   <li>start.uuid1.zap Redirects to the domain
 *   <li>login.uuid1.zap Handles the login, generates a token used by both the app and the api
 *   <li>app.uuid1.zap The actual app (cannot be accessed except via start)
 *   <li>api.uuid1.zap An API used by the app
 * </ul>
 *
 * Note that there is no direct link to the Login page, start.uuid1 redirects to a unique URL
 */
public class UuidLoginRootDir extends TestAuthDirectory {

    private Set<String> tokens = new HashSet<>();

    private static final Logger LOGGER = LogManager.getLogger(UuidLoginRootDir.class);

    private static final List<String> TEST_PAGES = List.of("test1", "test2", "test3", "test4");

    private Set<String> loginPages = new HashSet<>();

    public UuidLoginRootDir(TestProxyServer server, String name) {
        super(server, name);
        server.addDomainListener(
                "https://start.uuid1.zap",
                new DevHttpSenderListener(this.getServer()) {
                    @Override
                    public void onHttpResponseReceive(
                            HttpMessage msg, int initiator, HttpSender sender) {
                        try {
                            if (msg.getRequestHeader().getURI().getPath().length() <= 1) {
                                String uuid = UUID.randomUUID().toString();
                                loginPages.add(uuid);
                                DevUtils.setRedirect(msg, "https://login.uuid1.zap/" + uuid);
                            }
                        } catch (URIException e) {
                            LOGGER.error(e.getMessage(), e);
                        }
                    }
                });
        server.addDomainListener(
                "https://login.uuid1.zap",
                new DevHttpSenderListener(this.getServer()) {
                    @Override
                    public void onHttpResponseReceive(
                            HttpMessage msg, int initiator, HttpSender sender) {
                        String page = getPageName(msg);
                        String body = "";
                        boolean redirect = false;

                        try {
                            if (loginPages.contains(page)) {
                                if (HttpRequestHeader.POST.equals(
                                        msg.getRequestHeader().getMethod())) {
                                    if ("test@test.com".equals(DevUtils.getFormParam(msg, "user"))
                                            && "password123"
                                                    .equals(
                                                            DevUtils.getFormParam(
                                                                    msg, "password"))) {
                                        // Success. Remove the UUID so it cannot be reused.
                                        loginPages.remove(page);
                                        DevUtils.setRedirect(
                                                msg, "https://app.uuid1.zap/?token=" + getToken());
                                        redirect = true;
                                    } else {
                                        body =
                                                server.getTextFile(
                                                                UuidLoginRootDir.this, "login.html")
                                                        .replace(
                                                                "<!-- RESULT -->",
                                                                "Bad username or password");
                                    }
                                } else {
                                    body = server.getTextFile(UuidLoginRootDir.this, "login.html");
                                }
                                msg.setResponseBody(body);
                                if (redirect) {
                                    msg.getResponseHeader()
                                            .setContentLength(msg.getResponseBody().length());
                                } else {
                                    msg.setResponseHeader(
                                            TestProxyServer.getDefaultResponseHeader(
                                                    TestProxyServer.CONTENT_TYPE_HTML_UTF8,
                                                    msg.getResponseBody().length()));
                                }

                            } else {
                                // Fallback for CSS etc pages
                                server.handleFile(page, msg);
                            }
                        } catch (HttpMalformedHeaderException e) {
                            LOGGER.error(e.getMessage(), e);
                        }
                    }
                });
        server.addDomainListener(
                "https://app.uuid1.zap",
                new DevHttpSenderListener(this.getServer()) {
                    @Override
                    public void onHttpResponseReceive(
                            HttpMessage msg, int initiator, HttpSender sender) {
                        try {
                            String page = getPageName(msg);
                            if (!HttpRequestHeader.GET.equals(msg.getRequestHeader().getMethod())) {
                                // Passthrough
                            } else if (TestDirectory.INDEX_PAGE.equals(page)) {
                                String body = server.getTextFile(UuidLoginRootDir.this, "app.html");

                                msg.setResponseBody(body);
                                msg.setResponseHeader(
                                        TestProxyServer.getDefaultResponseHeader(
                                                TestProxyServer.CONTENT_TYPE_HTML_UTF8,
                                                msg.getResponseBody().length()));
                            } else if (TEST_PAGES.contains(page)) {
                                String body =
                                        server.getTextFile(UuidLoginRootDir.this, "app-test.html");

                                msg.setResponseBody(body);
                                msg.setResponseHeader(
                                        TestProxyServer.getDefaultResponseHeader(
                                                TestProxyServer.CONTENT_TYPE_HTML_UTF8,
                                                msg.getResponseBody().length()));
                            }
                        } catch (Exception e) {
                            LOGGER.error(e.getMessage(), e);
                        }
                    }
                });
        server.addDomainListener(
                "https://api.uuid1.zap",
                new DevHttpSenderListener(this.getServer()) {
                    @Override
                    public void onHttpResponseReceive(
                            HttpMessage msg, int initiator, HttpSender sender) {
                        boolean redirect = false;
                        String token = msg.getRequestHeader().getHeader("Authorization");
                        if (!HttpRequestHeader.GET.equals(msg.getRequestHeader().getMethod())) {
                            // Passthrough
                        } else if (!tokens.contains(token)) {
                            DevUtils.setRedirect(msg, "https://start.uuid1.zap");
                            redirect = true;
                        } else {
                            String body = "[\"test1\", \"test2\", \"test3\"]";

                            msg.setResponseBody(body);

                            try {
                                msg.setResponseHeader(
                                        TestProxyServer.getDefaultResponseHeader(
                                                TestProxyServer.CONTENT_TYPE_HTML_UTF8,
                                                msg.getResponseBody().length()));
                            } catch (HttpMalformedHeaderException e) {
                                LOGGER.error(e.getMessage(), e);
                            }
                        }
                        if (!redirect) {
                            msg.getResponseHeader()
                                    .setHeader(
                                            "Access-Control-Allow-Origin", "https://app.uuid1.zap");
                            msg.getResponseHeader()
                                    .setHeader("Access-Control-Allow-Headers", "Authorization");
                        }
                    }
                });
    }

    private String getToken() {
        String token = RandomStringUtils.secure().nextAlphanumeric(32);
        tokens.add(token);
        return token;
    }
}
