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
package org.zaproxy.addon.dev.auth.basicHttp;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.dev.TestAuthDirectory;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

/**
 * An auth directory that uses HTTP Basic authentication. All pages require valid Basic auth
 * credentials. Returns 401 with WWW-Authenticate when credentials are missing or invalid.
 */
public class BasicHttpDir extends TestAuthDirectory {

    private static final String STATUS_UNAUTHORIZED = "401 Unauthorized";
    private static final String REALM = "ZAP Dev";
    private static final Logger LOGGER = LogManager.getLogger(BasicHttpDir.class);

    public BasicHttpDir(TestProxyServer server, String name) {
        super(server, name);
        this.addPage(new BasicHttpVerificationPage(server));
    }

    /**
     * Extracts the username from the Basic auth Authorization header. Returns null if the header is
     * missing, invalid, or credentials are not valid.
     */
    String getUsernameFromMessage(HttpMessage msg) {
        String[] creds =
                parseBasicAuthCredentials(
                        msg.getRequestHeader().getHeader(HttpHeader.AUTHORIZATION));
        if (creds != null && isValid(creds[0], creds[1])) {
            return creds[0];
        }
        return null;
    }

    private static String[] parseBasicAuthCredentials(String authHeader) {
        if (authHeader == null || !authHeader.regionMatches(true, 0, "Basic ", 0, 6)) {
            return null;
        }
        String encoded = authHeader.substring(6).trim();
        try {
            String decoded =
                    new String(Base64.getDecoder().decode(encoded), StandardCharsets.UTF_8);
            int colonIndex = decoded.indexOf(':');
            if (colonIndex >= 0) {
                return new String[] {
                    decoded.substring(0, colonIndex), decoded.substring(colonIndex + 1)
                };
            }
        } catch (IllegalArgumentException e) {
            LOGGER.debug("Invalid Base64 in Authorization header", e);
        }
        return null;
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
        String username = null;
        String password = null;

        String[] creds =
                parseBasicAuthCredentials(
                        msg.getRequestHeader().getHeader(HttpHeader.AUTHORIZATION));
        if (creds != null) {
            username = creds[0];
            password = creds[1];
        }

        if (!isValid(username, password)) {
            sendUnauthorized(msg);
            return;
        }

        super.handleMessage(ctx, msg);
    }

    private void sendUnauthorized(HttpMessage msg) {
        try {
            msg.setResponseBody(getServer().getTextFile(this, "401.html"));
            msg.setResponseHeader(
                    TestProxyServer.getDefaultResponseHeader(
                            STATUS_UNAUTHORIZED, "text/html", msg.getResponseBody().length()));
            msg.getResponseHeader()
                    .setHeader(HttpHeader.WWW_AUTHENTICATE, "Basic realm=\"" + REALM + "\"");
        } catch (HttpMalformedHeaderException e) {
            LOGGER.error(e.getMessage(), e);
        }
    }
}
