/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import net.sf.json.JSON;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.dev.api.openapi.simpleAuth.OpenApiSimpleAuthDir;
import org.zaproxy.addon.dev.api.openapi.simpleUnauth.OpenApiSimpleUnauthDir;
import org.zaproxy.addon.dev.auth.jsonMultipleCookies.JsonMultipleCookiesDir;
import org.zaproxy.addon.dev.auth.nonStdJsonBearer.NonStdJsonBearerDir;
import org.zaproxy.addon.dev.auth.passswordAddedNoSubmit.PasswordAddedNoSubmitDir;
import org.zaproxy.addon.dev.auth.passwordAddedJson.PasswordAddedJsonDir;
import org.zaproxy.addon.dev.auth.passwordHiddenJson.PasswordHiddenJsonDir;
import org.zaproxy.addon.dev.auth.passwordNewPage.PasswordNewPageDir;
import org.zaproxy.addon.dev.auth.simpleJson.SimpleJsonDir;
import org.zaproxy.addon.dev.auth.simpleJsonBearer.SimpleJsonBearerDir;
import org.zaproxy.addon.dev.auth.simpleJsonBearerCookie.SimpleJsonBearerCookieDir;
import org.zaproxy.addon.dev.auth.simpleJsonBearerJsCookie.SimpleJsonBearerJsCookieDir;
import org.zaproxy.addon.dev.auth.simpleJsonCookie.SimpleJsonCookieDir;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.addon.network.server.HttpMessageHandler;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;
import org.zaproxy.addon.network.server.Server;

public class TestProxyServer {

    public static final String STATUS_OK = "200 OK";
    public static final String STATUS_FORBIDDEN = "403 Forbidden";
    public static final String STATUS_NOT_FOUND = "404 Not Found";
    public static final String STATUS_REDIRECT = "302 Found";

    private static final Logger LOGGER = LogManager.getLogger(TestProxyServer.class);

    private ExtensionDev extension;
    private ExtensionNetwork extensionNetwork;
    private Server server;

    private TestDirectory root;

    public TestProxyServer(ExtensionDev extension, ExtensionNetwork extensionNetwork) {
        this.extension = extension;
        this.extensionNetwork = extensionNetwork;

        // This is the hierarchy of directories and pages.
        root = new TestDirectory(this, "");

        TestDirectory authDir = new TestDirectory(this, "auth");
        authDir.addDirectory(new SimpleJsonDir(this, "simple-json"));
        authDir.addDirectory(new SimpleJsonBearerDir(this, "simple-json-bearer"));
        authDir.addDirectory(new NonStdJsonBearerDir(this, "non-std-json-bearer"));
        authDir.addDirectory(new SimpleJsonBearerCookieDir(this, "simple-json-bearer-cookie"));
        authDir.addDirectory(new SimpleJsonBearerJsCookieDir(this, "simple-json-bearer-js-cookie"));
        authDir.addDirectory(new SimpleJsonCookieDir(this, "simple-json-cookie"));
        authDir.addDirectory(new PasswordAddedJsonDir(this, "password-added-json"));
        authDir.addDirectory(new PasswordHiddenJsonDir(this, "password-hidden-json"));
        authDir.addDirectory(new PasswordNewPageDir(this, "password-new-page"));
        authDir.addDirectory(new PasswordAddedNoSubmitDir(this, "password-added-json"));
        authDir.addDirectory(new JsonMultipleCookiesDir(this, "json-multiple-cookies"));

        TestDirectory apiDir = new TestDirectory(this, "api");
        TestDirectory openapiDir = new TestDirectory(this, "openapi");
        apiDir.addDirectory(openapiDir);
        openapiDir.addDirectory(new OpenApiSimpleAuthDir(this, "simple-auth"));
        openapiDir.addDirectory(new OpenApiSimpleUnauthDir(this, "simple-unauth"));

        TestDirectory htmlDir = new TestDirectory(this, "html");
        TestDirectory locStoreDir = new TestDirectory(this, "localStorage");
        TestDirectory sessStoreDir = new TestDirectory(this, "sessionStorage");
        htmlDir.addDirectory(locStoreDir);
        htmlDir.addDirectory(sessStoreDir);

        root.addDirectory(authDir);
        root.addDirectory(apiDir);
        root.addDirectory(htmlDir);
    }

    private Server getServer() {
        if (server == null) {
            this.server = extensionNetwork.createHttpServer(new TestListener());
        }
        return server;
    }

    /** The server is started after initialisation so that the parameters will have been loaded. */
    public void start() {
        try {
            getServer()
                    .start(
                            extension.getDevParam().getTestHost(),
                            extension.getDevParam().getTestPort());
        } catch (IOException e) {
            LOGGER.warn("An error occurred while starting the server.", e);
        }
    }

    public void stop() {
        if (server == null) {
            return;
        }

        try {
            getServer().stop();
        } catch (IOException e) {
            LOGGER.debug("An error occurred while stopping the server.", e);
        }
    }

    public String getTextFile(String name) {
        return getTextFile(root, name);
    }

    public String getTextFile(TestDirectory dir, String name) {
        StringBuilder sb = new StringBuilder();
        sb.append(extension.getDevParam().getBaseDirectory());
        if (!sb.toString().endsWith("/")) {
            sb.append("/");
        }
        if (dir != null) {
            sb.append(dir.getHierarchicName());
        }
        sb.append("/");
        sb.append(name);

        File f = new File(sb.toString());

        if (!f.exists()) {
            return null;
        }
        // Quick way to read a small text file
        try {
            return Files.readString(f.toPath(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            LOGGER.error(e.getMessage(), e);
            return null;
        }
    }

    public static String getDefaultResponseHeader(String contentType, int contentLength) {
        return getDefaultResponseHeader(STATUS_OK, contentType, contentLength);
    }

    public static String getDefaultResponseHeader(
            String responseStatus, String contentType, int contentLength) {
        StringBuilder sb = new StringBuilder(250);

        sb.append("HTTP/1.1 ").append(responseStatus).append("\r\n");
        sb.append("Pragma: no-cache\r\n");
        sb.append("Cache-Control: no-cache, no-store, must-revalidate\r\n");
        sb.append("Access-Control-Allow-Methods: GET,POST,OPTIONS\r\n");
        sb.append("Access-Control-Allow-Headers: ZAP-Header\r\n");
        sb.append("X-Frame-Options: DENY\r\n");
        sb.append("X-XSS-Protection: 1; mode=block\r\n");
        sb.append("X-Content-Type-Options: nosniff\r\n");
        sb.append("X-Clacks-Overhead: GNU Terry Pratchett\r\n");
        sb.append("Content-Length: ").append(contentLength).append("\r\n");
        sb.append("Content-Type: ").append(contentType).append("\r\n");

        return sb.toString();
    }

    public void handleFile(TestDirectory dir, String name, HttpMessage msg) {
        try {
            String body = getTextFile(dir, name);

            if (body == null) {
                LOGGER.debug("Failed to find file {}", name);
                body = getTextFile(root, "404.html");
                msg.setResponseBody(body);
                msg.setResponseHeader(
                        getDefaultResponseHeader(
                                STATUS_NOT_FOUND, "text/html", msg.getResponseBody().length()));
            } else {
                msg.setResponseBody(body);
                String contentType = "text/plain"; // Fallback
                if (name.endsWith(".html")) {
                    contentType = "text/html";
                } else if (name.endsWith(".css")) {
                    contentType = "text/css";
                } else if (name.endsWith(".js")) {
                    contentType = "text/javascript";
                } else {
                    LOGGER.error("Unexpected tutorial file extension: {}", name);
                }
                msg.setResponseHeader(
                        getDefaultResponseHeader(contentType, msg.getResponseBody().length()));
            }
        } catch (HttpMalformedHeaderException e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    public void setJsonResponse(JSON json, HttpMessage msg) {
        this.setJsonResponse(STATUS_OK, json, msg);
    }

    public void setJsonResponse(String responseStatus, JSON json, HttpMessage msg) {
        try {
            String body = json.toString();
            LOGGER.debug("{} returning {}", msg.getRequestHeader().getURI(), body);
            msg.setResponseBody(body);
            msg.setResponseHeader(
                    getDefaultResponseHeader(
                            responseStatus, "application/json", msg.getResponseBody().length()));
        } catch (HttpMalformedHeaderException e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    public void redirect(String url, HttpMessage msg) {
        try {
            msg.setResponseHeader(getDefaultResponseHeader(STATUS_REDIRECT, "text/html", 0));
            msg.getResponseHeader().setHeader(HttpHeader.LOCATION, url);
        } catch (HttpMalformedHeaderException e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    private class TestListener implements HttpMessageHandler {

        @Override
        public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
            ctx.overridden();

            String path = msg.getRequestHeader().getURI().getEscapedPath();
            TestDirectory dir = root;
            String[] dirs = path.split("/");
            for (int i = 1; i < dirs.length; i++) {
                TestDirectory d = dir.getSubDir(dirs[i]);
                if (d != null) {
                    dir = d;
                } else {
                    break;
                }
            }
            dir.handleMessage(ctx, msg);
        }
    }
}
