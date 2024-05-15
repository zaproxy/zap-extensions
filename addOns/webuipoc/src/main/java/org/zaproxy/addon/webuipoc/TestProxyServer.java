/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.webuipoc;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import net.sf.json.JSON;
import org.apache.commons.text.StringEscapeUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpInputStream;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpOutputStream;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.addon.network.server.HttpMessageHandler;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;
import org.zaproxy.addon.network.server.Server;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.network.HttpRequestBody;

public class TestProxyServer {

    public static final String STATUS_OK = "200 OK";
    public static final String STATUS_FORBIDDEN = "403 Forbidden";
    public static final String STATUS_NOT_FOUND = "404 Not Found";
    public static final String STATUS_REDIRECT = "302 Found";

    public static final String INDEX_PAGE = "index.html";
    public static final String ERROR_404_PAGE = "404.html";
    public static final String API_PATH = "/api/";

    private static final Logger LOGGER = LogManager.getLogger(TestProxyServer.class);

    private ExtensionWebUiPoc extension;
    private ExtensionNetwork extensionNetwork;
    private Server server;

    public TestProxyServer(ExtensionWebUiPoc extension, ExtensionNetwork extensionNetwork) {
        this.extension = extension;
        this.extensionNetwork = extensionNetwork;
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
            getServer().start("localhost", 1337);
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
        // If this CSP is causing you problems then talk to the ZAP team
        sb.append(
                "Content-Security-Policy: default-src 'none'; script-src 'self'; connect-src 'self'; "
                        + "child-src 'self'; img-src 'self' data:; font-src 'self' data:; style-src 'self'\r\n");
        sb.append("X-Frame-Options: SAMEORIGIN\r\n");
        sb.append("X-XSS-Protection: 1; mode=block\r\n");
        sb.append("X-Content-Type-Options: nosniff\r\n");
        sb.append("X-Clacks-Overhead: GNU Terry Pratchett\r\n");
        sb.append("Content-Length: ").append(contentLength).append("\r\n");
        sb.append("Content-Type: ").append(contentType).append("\r\n");

        return sb.toString();
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

    private static void handleApiRequest(HttpMessageHandlerContext ctx, HttpMessage msg)
            throws IOException {
        String requestHeaderStr = msg.getRequestHeader().toString();
        HttpRequestHeader requestHeader =
                new HttpRequestHeader(requestHeaderStr.replaceFirst(API_PATH, "/"));
        requestHeader.setSenderAddress(msg.getRequestHeader().getSenderAddress());
        HttpRequestBody reqBody = msg.getRequestBody();

        InputStream is = new ByteArrayInputStream(reqBody.getBytes());
        Socket socket =
                new Socket() {
                    @Override
                    public InputStream getInputStream() throws IOException {
                        return is;
                    }
                };
        HttpInputStream httpIn = new HttpInputStream(socket);
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        HttpOutputStream httpOut = new HttpOutputStream(os);

        HttpMessage apiResponse =
                API.getInstance()
                        .handleApiRequest(requestHeader, httpIn, httpOut, ctx.isRecursive());

        if (apiResponse != null) {
            if (apiResponse.getRequestHeader().isEmpty()) {
                ctx.close();
                return;
            }

            msg.setResponseHeader(apiResponse.getResponseHeader());
            msg.setResponseBody(apiResponse.getResponseBody());

            ctx.overridden();
        }
    }

    protected static boolean isApiRequest(HttpMessage msg) {
        String path = msg.getRequestHeader().getURI().getEscapedPath();
        return path.startsWith("/UI/")
                || path.startsWith("/JSON/")
                || path.startsWith("/script.js");
    }

    private class TestListener implements HttpMessageHandler {

        @Override
        public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
            ctx.overridden();

            try {
                String path = msg.getRequestHeader().getURI().getEscapedPath();

                if (isApiRequest(msg)) {
                    handleApiRequest(ctx, msg);
                    return;
                }

                File file = new File(extension.getBaseDirectory(), path);
                String name = getPageName(msg);
                String body;

                if (file.isDirectory()) {
                    file = new File(file, INDEX_PAGE);
                    name = INDEX_PAGE;
                }
                if (!file.exists()) {
                    LOGGER.debug("File does not exist: {}", file.getAbsolutePath());
                    file = new File(extension.getBaseDirectory(), ERROR_404_PAGE);
                    name = ERROR_404_PAGE;
                }
                body = Files.readString(file.toPath(), StandardCharsets.UTF_8);
                if (INDEX_PAGE.equals(name) && "/".equals(path)) {
                    // List the top level directories
                    String[] directories =
                            extension
                                    .getBaseDirectory()
                                    .list(
                                            new FilenameFilter() {
                                                @Override
                                                public boolean accept(File current, String name) {
                                                    return new File(current, name).isDirectory();
                                                }
                                            });
                    StringBuilder sb = new StringBuilder();
                    sb.append("<ul>");
                    Arrays.stream(directories)
                            .forEach(
                                    d -> {
                                        String safeDir = StringEscapeUtils.escapeHtml4(d);
                                        sb.append("<li><a href=\"")
                                                .append(safeDir)
                                                .append("\">")
                                                .append(safeDir)
                                                .append("</a>\n");
                                    });
                    sb.append("</ul>");
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
            } catch (Exception e) {
                LOGGER.error(e.getMessage(), e);
            }
        }
    }
}
