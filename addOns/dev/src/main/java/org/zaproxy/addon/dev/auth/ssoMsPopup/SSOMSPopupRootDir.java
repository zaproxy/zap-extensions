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
package org.zaproxy.addon.dev.auth.ssoMsPopup;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import net.sf.json.JSONException;
import net.sf.json.JSONObject;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.dev.DevHttpSenderListener;
import org.zaproxy.addon.dev.DevUtils;
import org.zaproxy.addon.dev.TestAuthDirectory;
import org.zaproxy.addon.dev.TestDirectory;
import org.zaproxy.addon.dev.TestProxyServer;

/**
 * A test app which uses a popup window for MS Online auth:
 *
 * <ul>
 *   <li>app.sso-ms-popup.zap The main app, which opens a popup window for authentication
 *   <li>login.microsoftonline.popup.zap Handles the login in the popup window
 * </ul>
 */
public class SSOMSPopupRootDir extends TestAuthDirectory {

    private Set<String> tokens = new HashSet<>();

    private static final Logger LOGGER = LogManager.getLogger(SSOMSPopupRootDir.class);

    private static final List<String> TEST_PAGES = List.of("test1", "test2", "test3", "test4");

    public SSOMSPopupRootDir(TestProxyServer server, String name) {
        super(server, name);
        server.addDomainListener(
                "https://login.microsoftonline.popup.zap",
                new DevHttpSenderListener(this.getServer()) {
                    @Override
                    public void onHttpResponseReceive(
                            HttpMessage msg, int initiator, HttpSender sender) {
                        String page = getPageName(msg);
                        try {
                            String service = DevUtils.getUrlParam(msg, "service");
                            if ("authorize".equals(page)) {
                                delay(msg);
                                if (service == null) {
                                    String body =
                                            server.getTextFile(SSOMSPopupRootDir.this, "error.html")
                                                    .replace(
                                                            "<!-- ERROR -->",
                                                            "No service specified");
                                    msg.setResponseBody(body);
                                    msg.setResponseHeader(
                                            TestProxyServer.getDefaultResponseHeader(
                                                    TestProxyServer.CONTENT_TYPE_HTML_UTF8,
                                                    msg.getResponseBody().length()));
                                } else if (HttpRequestHeader.POST.equals(
                                        msg.getRequestHeader().getMethod())) {
                                    String postData = msg.getRequestBody().toString();
                                    try {
                                        JSONObject jsonObject = JSONObject.fromObject(postData);
                                        JSONObject response = new JSONObject();
                                        if ("test@test.com".equals(jsonObject.getString("user"))
                                                && "password123"
                                                        .equals(jsonObject.getString("password"))) {
                                            response.put("result", "OK");
                                            response.put("token", getToken());
                                        } else {
                                            response.put("result", "FAIL");
                                        }
                                        getServer().setJsonResponse(response, msg);
                                    } catch (JSONException e) {
                                        LOGGER.debug("Unable to parse as JSON: {}", postData, e);
                                    }
                                } else {
                                    String body =
                                            server.getTextFile(
                                                    SSOMSPopupRootDir.this, "login.html");
                                    body = body.replace("<!-- SERVICE -->", service);
                                    msg.setResponseBody(body);
                                    msg.setResponseHeader(
                                            TestProxyServer.getDefaultResponseHeader(
                                                    TestProxyServer.CONTENT_TYPE_HTML_UTF8,
                                                    msg.getResponseBody().length()));
                                }
                            } else if ("user".equals(page)
                                    && HttpRequestHeader.POST.equals(
                                            msg.getRequestHeader().getMethod())) {
                                delay(msg);
                                String postData = msg.getRequestBody().toString();
                                try {
                                    JSONObject jsonObject = JSONObject.fromObject(postData);
                                    JSONObject response = new JSONObject();
                                    String user = jsonObject.getString("user");
                                    if (user.contains("@")) {
                                        response.put("result", "OK");
                                    } else {
                                        response.put("result", "FAIL");
                                    }
                                    response.put("user", user);
                                    getServer().setJsonResponse(response, msg);
                                } catch (JSONException e) {
                                    LOGGER.debug("Unable to parse as JSON: {}", postData, e);
                                }
                            }
                        } catch (Exception e) {
                            LOGGER.error(e.getMessage(), e);
                        }
                    }
                });
        server.addDomainListener(
                "https://app.sso-ms-popup.zap",
                new DevHttpSenderListener(this.getServer()) {
                    @Override
                    public void onHttpResponseReceive(
                            HttpMessage msg, int initiator, HttpSender sender) {
                        try {
                            String page = getPageName(msg);
                            if (!HttpRequestHeader.GET.equals(msg.getRequestHeader().getMethod())) {
                                // Passthrough
                            } else if (TestDirectory.INDEX_PAGE.equals(page)) {
                                delay(msg);
                                String body =
                                        server.getTextFile(SSOMSPopupRootDir.this, "app.html");
                                msg.setResponseBody(body);
                                msg.setResponseHeader(
                                        TestProxyServer.getDefaultResponseHeader(
                                                TestProxyServer.CONTENT_TYPE_HTML_UTF8,
                                                msg.getResponseBody().length()));
                            } else if ("user".equals(page)) {
                                delay(msg);
                                String token = msg.getRequestHeader().getHeader("Authorization");
                                if (token == null) {
                                    token =
                                            extractTokenCookie(
                                                    msg.getRequestHeader().getHeader("Cookie"));
                                }
                                JSONObject response = new JSONObject();
                                if (token != null && tokens.contains(token)) {
                                    response.put("result", "OK");
                                    response.put("user", "test@test.com");
                                } else {
                                    response.put("result", "FAIL");
                                }
                                getServer().setJsonResponse(response, msg);
                            } else if (TEST_PAGES.contains(page)) {
                                delay(msg);
                                String body =
                                        server.getTextFile(SSOMSPopupRootDir.this, "app-test.html");
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
    }

    private String getToken() {
        String token = RandomStringUtils.secure().nextAlphanumeric(32);
        tokens.add(token);
        return token;
    }

    private static String extractTokenCookie(String cookieHeader) {
        if (cookieHeader == null) {
            return null;
        }
        for (String part : cookieHeader.split(";")) {
            String trimmed = part.trim();
            if (trimmed.startsWith("token=")) {
                return trimmed.substring("token=".length());
            }
        }
        return null;
    }

    private void delay(HttpMessage msg) {
        String delayStr = DevUtils.getUrlParam(msg, "ms-delay");
        if (delayStr != null) {
            try {
                Thread.sleep(TimeUnit.SECONDS.toMillis(Integer.parseInt(delayStr)));
            } catch (Exception e) {
                // Ignore
            }
        }
    }
}
