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
package org.zaproxy.addon.dev.auth.ssoMs;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import net.sf.json.JSONException;
import net.sf.json.JSONObject;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
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
 *   <li>start.sso-ms.zap Redirects to the sso domain
 *   <li>login.microsoftonline.zap Handles the login, generates a token used by both the app and the
 *       api
 *   <li>app.sso-ms.zap The actual app (cannot be accessed except via sso)
 *   <li>api.sso-ms.zap An API used by the app
 * </ul>
 */
public class SSOMSRootDir extends TestAuthDirectory {

    private Set<String> tokens = new HashSet<>();

    private static final Logger LOGGER = LogManager.getLogger(SSOMSRootDir.class);

    private static final List<String> TEST_PAGES = List.of("test1", "test2", "test3", "test4");

    private static final String LOGIN_URL =
            "https://login.microsoftonline.zap/common/oauth2/v2.0/authorize?service=app.sso-ms.zap";

    public SSOMSRootDir(TestProxyServer server, String name) {
        super(server, name);
        server.addDomainListener(
                "https://start.sso-ms.zap",
                new DevHttpSenderListener(this.getServer()) {
                    @Override
                    public void onHttpResponseReceive(
                            HttpMessage msg, int initiator, HttpSender sender) {
                        delay(msg);
                        try {
                            URI uri = msg.getRequestHeader().getURI();
                            if (uri.getPath().length() <= 1) {
                                // Redirect to SSO passing on any URL params
                                DevUtils.setRedirect(
                                        msg,
                                        LOGIN_URL
                                                + (uri.getQuery() == null
                                                        ? ""
                                                        : "&" + uri.getQuery()));
                            }
                        } catch (URIException e) {
                            LOGGER.error(e.getMessage(), e);
                        }
                    }
                });
        server.addDomainListener(
                "https://login.microsoftonline.zap",
                new DevHttpSenderListener(this.getServer()) {
                    @Override
                    public void onHttpResponseReceive(
                            HttpMessage msg, int initiator, HttpSender sender) {
                        String page = getPageName(msg);
                        try {
                            String body = "";
                            String service = DevUtils.getUrlParam(msg, "service");
                            if ("authorize".equals(page)) {
                                delay(msg);
                                if (service == null) {
                                    body =
                                            server.getTextFile(SSOMSRootDir.this, "error.html")
                                                    .replace(
                                                            "<!-- ERROR -->",
                                                            "No service specified");

                                } else {
                                    if (HttpRequestHeader.POST.equals(
                                            msg.getRequestHeader().getMethod())) {

                                        String postData = msg.getRequestBody().toString();
                                        JSONObject jsonObject;

                                        try {
                                            jsonObject = JSONObject.fromObject(postData);
                                            JSONObject response = new JSONObject();

                                            if ("test@test.com".equals(jsonObject.getString("user"))
                                                    && "password123"
                                                            .equals(
                                                                    jsonObject.getString(
                                                                            "password"))) {
                                                response.put("result", "OK");
                                                response.put("token", getToken());
                                            } else {
                                                response.put("result", "FAIL");
                                            }
                                            getServer().setJsonResponse(response, msg);

                                        } catch (JSONException e) {
                                            LOGGER.debug(
                                                    "Unable to parse as JSON: {}", postData, e);
                                        }
                                    } else {
                                        body = server.getTextFile(SSOMSRootDir.this, "login.html");
                                        body = body.replace("<!-- SERVICE -->", service);
                                        msg.setResponseBody(body);
                                        msg.setResponseHeader(
                                                TestProxyServer.getDefaultResponseHeader(
                                                        TestProxyServer.CONTENT_TYPE_HTML_UTF8,
                                                        msg.getResponseBody().length()));
                                    }
                                }
                            } else if ("user".equals(page)
                                    && HttpRequestHeader.POST.equals(
                                            msg.getRequestHeader().getMethod())) {
                                delay(msg);

                                String postData = msg.getRequestBody().toString();
                                JSONObject jsonObject;

                                try {
                                    jsonObject = JSONObject.fromObject(postData);
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
                "https://app.sso-ms.zap",
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
                                String body = server.getTextFile(SSOMSRootDir.this, "app.html");

                                msg.setResponseBody(body);
                                msg.setResponseHeader(
                                        TestProxyServer.getDefaultResponseHeader(
                                                TestProxyServer.CONTENT_TYPE_HTML_UTF8,
                                                msg.getResponseBody().length()));
                            } else if (TEST_PAGES.contains(page)) {
                                delay(msg);
                                String body =
                                        server.getTextFile(SSOMSRootDir.this, "app-test.html");

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
                "https://api.sso-ms.zap",
                new DevHttpSenderListener(this.getServer()) {
                    @Override
                    public void onHttpResponseReceive(
                            HttpMessage msg, int initiator, HttpSender sender) {
                        delay(msg);
                        boolean redirect = false;
                        String token = msg.getRequestHeader().getHeader("Authorization");
                        if (!HttpRequestHeader.GET.equals(msg.getRequestHeader().getMethod())) {
                            // Passthrough
                        } else if (!tokens.contains(token)) {
                            DevUtils.setRedirect(msg, LOGIN_URL);
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
                                            "Access-Control-Allow-Origin",
                                            "https://app.sso-ms.zap");
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
