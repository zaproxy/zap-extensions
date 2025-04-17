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
package org.zaproxy.addon.dev.auth.sso1;

import java.util.HashSet;
import java.util.Set;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.addon.dev.DevProxyHandler;
import org.zaproxy.addon.dev.DevUtils;
import org.zaproxy.addon.dev.TestAuthDirectory;
import org.zaproxy.addon.dev.TestDirectory;
import org.zaproxy.addon.dev.TestProxyServer;

/** TODO add description */
public class SSO1RootDir extends TestAuthDirectory {

    private Set<String> tokens = new HashSet<>();

    private static final Logger LOGGER = LogManager.getLogger(SSO1RootDir.class);

    public SSO1RootDir(TestProxyServer server, String name) {
        super(server, name);

        server.addDomainListener(
                "https://start.sso1.zap",
                new DevProxyHandler() {
                    @Override
                    public boolean onHttpRequestSend(HttpMessage msg) {
                        // Always redirect to SSO with a "return" param
                        DevUtils.setRedirect(msg, "https://sso.sso1.zap/?service=app.sso1.zap");
                        return true;
                    }
                });
        server.addDomainListener(
                "https://sso.sso1.zap",
                new DevProxyHandler() {
                    @Override
                    public boolean onHttpRequestSend(HttpMessage msg) {
                        // Initial hack to show this works
                        String page = getPageName(msg);

                        try {
                            String body;
                            String service = DevUtils.getUrlParam(msg, "service");
                            if (TestDirectory.INDEX_PAGE.equals(page)) {
                                if (service == null) {
                                    body =
                                            server.getTextFile(SSO1RootDir.this, "error.html")
                                                    .replace(
                                                            "<!-- ERROR -->",
                                                            "No service specified");

                                } else {
                                    if (HttpRequestHeader.POST.equals(
                                            msg.getRequestHeader().getMethod())) {
                                        if ("test@test.com"
                                                        .equals(DevUtils.getFormParam(msg, "user"))
                                                && "password123"
                                                        .equals(
                                                                DevUtils.getFormParam(
                                                                        msg, "password"))) {

                                            DevUtils.setRedirect(
                                                    msg,
                                                    "https://" + service + "/?token=" + getToken());
                                            return true;
                                        } else {
                                            body =
                                                    server.getTextFile(
                                                                    SSO1RootDir.this, "login.html")
                                                            .replace(
                                                                    "<!-- RESULT -->",
                                                                    "Bad username or password");
                                        }
                                    } else {
                                        body =
                                                server.getTextFile(SSO1RootDir.this, "login.html")
                                                        .replace("<!-- SERVICE -->", service);
                                    }
                                }
                            } else {
                                // CSS files etc
                                server.handleFile(page, msg);
                                return true;
                            }
                            msg.setResponseBody(body);
                            msg.setResponseHeader(
                                    new HttpResponseHeader(
                                            "HTTP/1.1 200 OK\r\n"
                                                    + "Content-Type: text/html; charset=UTF-8"));
                        } catch (Exception e) {
                            // TODO Auto-generated catch block
                            e.printStackTrace();
                        }
                        msg.getResponseHeader().setContentLength(msg.getResponseBody().length());
                        return true;
                    }
                });
        server.addDomainListener(
                "https://app.sso1.zap",
                new DevProxyHandler() {
                    @Override
                    public boolean onHttpRequestSend(HttpMessage msg) {
                        String token = DevUtils.getUrlParam(msg, "token");
                        if (!tokens.contains(token)) {
                            DevUtils.setRedirect(msg, "https://start.sso1.zap");
                            return true;
                        }
                        String body = server.getTextFile(SSO1RootDir.this, "app.html");

                        msg.setResponseBody(body);
                        try {
                            msg.setResponseHeader(
                                    new HttpResponseHeader(
                                            "HTTP/1.1 200 OK\r\n"
                                                    + "Content-Type: text/html; charset=UTF-8"));
                        } catch (HttpMalformedHeaderException e) {
                            LOGGER.error(e.getMessage(), e);
                        }

                        return true;
                    }
                });
        server.addDomainListener(
                "https://api.sso1.zap",
                new DevProxyHandler() {
                    @Override
                    public boolean onHttpRequestSend(HttpMessage msg) {
                        // TODO check token!
                        String token = DevUtils.getUrlParam(msg, "token");
                        if (!tokens.contains(token)) {
                            System.out.println("SBSB missing / wrong token " + token); // TODO
                            /*
                            DevUtils.setRedirect(msg, "https://start.sso1.zap");
                            return true;
                            */
                        }
                        String body = "[\"test1\", \"test2\", \"test3\"]";

                        msg.setResponseBody(body);
                        try {
                            msg.setResponseHeader(
                                    new HttpResponseHeader(
                                            "HTTP/1.1 200 OK\r\n"
                                                    + "Content-Type: application/json"));
                            msg.getResponseHeader()
                                    .setHeader(
                                            "Access-Control-Allow-Origin",
                                            "*"); // TODO app1.sso.zap?
                        } catch (HttpMalformedHeaderException e) {
                            LOGGER.error(e.getMessage(), e);
                        }

                        return true;
                    }
                });
    }

    private String getToken() {
        String token = RandomStringUtils.secure().nextAlphanumeric(32);
        tokens.add(token);
        System.out.println("SBSB generated token " + token); // TODO
        return token;
    }
}
