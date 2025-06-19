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
package org.zaproxy.addon.dev.auth.sso2;

import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
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
 *   <li>app.sso2.zap The app. Redirects to the login domain if no token in sessionStorage
 *   <li>login.sso2.zap Handles the login, redirects internally, passes the session token to the app
 *       base64 encoded
 *   <li>api.sso2.zap An API used by the app
 * </ul>
 */
public class SSO2RootDir extends TestAuthDirectory {

    private Set<String> loginTokens = new HashSet<>();
    private Set<String> apiTokens = new HashSet<>();

    private static final Logger LOGGER = LogManager.getLogger(SSO2RootDir.class);

    private static final List<String> TEST_PAGES = List.of("test1", "test2", "test3", "test4");

    public SSO2RootDir(TestProxyServer server, String name) {
        super(server, name);
        server.addDomainListener(
                "https://login.sso2.zap",
                new DevHttpSenderListener(this.getServer()) {
                    @Override
                    public void onHttpResponseReceive(
                            HttpMessage msg, int initiator, HttpSender sender) {
                        // Initial hack to show this works
                        String page = getPageName(msg);
                        boolean redirect = false;

                        try {
                            String body = "";
                            if (TestDirectory.INDEX_PAGE.equals(page)) {
                                if (HttpRequestHeader.POST.equals(
                                        msg.getRequestHeader().getMethod())) {
                                    if ("test@test.com".equals(DevUtils.getFormParam(msg, "user"))
                                            && "password123"
                                                    .equals(
                                                            DevUtils.getFormParam(
                                                                    msg, "password"))) {

                                        DevUtils.setRedirect(
                                                msg, "https://login.sso2.zap/" + getLoginToken());
                                        redirect = true;
                                    } else {
                                        body =
                                                server.getTextFile(SSO2RootDir.this, "login.html")
                                                        .replace(
                                                                "<!-- RESULT -->",
                                                                "Bad username or password");
                                    }
                                } else {
                                    body = server.getTextFile(SSO2RootDir.this, "login.html");
                                }
                                msg.setResponseBody(body);
                                if (!redirect) {
                                    msg.setResponseHeader(
                                            TestProxyServer.getDefaultResponseHeader(
                                                    TestProxyServer.CONTENT_TYPE_HTML_UTF8,
                                                    msg.getResponseBody().length()));
                                }
                            } else if (loginTokens.contains(page)) {
                                loginTokens.remove(page);
                                DevUtils.setRedirect(
                                        msg,
                                        "https://app.sso2.zap/?token="
                                                + Base64.getEncoder()
                                                        .encodeToString(getApiToken().getBytes()));
                            }
                        } catch (Exception e) {
                            LOGGER.error(e.getMessage(), e);
                        }
                        msg.getResponseHeader().setContentLength(msg.getResponseBody().length());
                    }
                });
        server.addDomainListener(
                "https://app.sso2.zap",
                new DevHttpSenderListener(this.getServer()) {
                    @Override
                    public void onHttpResponseReceive(
                            HttpMessage msg, int initiator, HttpSender sender) {
                        try {
                            String page = getPageName(msg);
                            if (!HttpRequestHeader.GET.equals(msg.getRequestHeader().getMethod())) {
                                // Passthrough
                            } else if (TestDirectory.INDEX_PAGE.equals(page)) {
                                String body = server.getTextFile(SSO2RootDir.this, "app.html");

                                msg.setResponseBody(body);
                                msg.setResponseHeader(
                                        TestProxyServer.getDefaultResponseHeader(
                                                TestProxyServer.CONTENT_TYPE_HTML_UTF8,
                                                msg.getResponseBody().length()));
                            } else if (TEST_PAGES.contains(page)) {
                                String body = server.getTextFile(SSO2RootDir.this, "app-test.html");

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
                "https://api.sso2.zap",
                new DevHttpSenderListener(this.getServer()) {
                    @Override
                    public void onHttpResponseReceive(
                            HttpMessage msg, int initiator, HttpSender sender) {
                        boolean redirect = false;
                        String token = msg.getRequestHeader().getHeader("Authorization");
                        if (!HttpRequestHeader.GET.equals(msg.getRequestHeader().getMethod())) {
                            // Passthrough
                        } else if (!apiTokens.contains(token)) {
                            DevUtils.setRedirect(msg, "https://login.sso2.zap");
                            redirect = true;
                        } else {
                            String body = "[\"test1\", \"test2\", \"test3\"]";

                            msg.setResponseBody(body);
                            try {
                                msg.setResponseHeader(
                                        new HttpResponseHeader(
                                                "HTTP/1.1 200 OK\r\n"
                                                        + "Content-Type: application/json"));
                            } catch (HttpMalformedHeaderException e) {
                                LOGGER.error(e.getMessage(), e);
                            }
                        }
                        if (!redirect) {
                            msg.getResponseHeader()
                                    .setHeader(
                                            "Access-Control-Allow-Origin", "https://app.sso2.zap");
                            msg.getResponseHeader()
                                    .setHeader("Access-Control-Allow-Headers", "Authorization");
                        }
                    }
                });
    }

    private String getLoginToken() {
        String token = RandomStringUtils.secure().nextAlphanumeric(32);
        loginTokens.add(token);
        return token;
    }

    private String getApiToken() {
        String token = RandomStringUtils.secure().nextAlphanumeric(32);
        apiTokens.add(token);
        return token;
    }
}
