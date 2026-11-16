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
package org.zaproxy.addon.openapitest.simpleoauth2;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import net.sf.json.JSONObject;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.dev.TestPage;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

/** The token endpoint, it supports the password grant. */
public class OpenApiOAuth2TokenPage extends TestPage {

    static final String BASIC_PREFIX = "Basic ";
    static final String PASSWORD_GRANT = "password";

    private static final String STATUS_BAD_REQUEST = "400 Bad Request";

    public OpenApiOAuth2TokenPage(TestProxyServer server) {
        super(server, "token");
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
        String[] client = getClientCredentials(msg);
        if (!getParent().isValidClient(client[0], client[1])) {
            getServer()
                    .setJsonResponse(
                            OpenApiSimpleOAuth2Dir.STATUS_UNAUTHORIZED,
                            errorJson("invalid_client", "Client authentication failed"),
                            msg);
            return;
        }
        if (!PASSWORD_GRANT.equals(getFormParameter(msg, "grant_type"))) {
            getServer()
                    .setJsonResponse(
                            STATUS_BAD_REQUEST,
                            errorJson("unsupported_grant_type", "Only the password grant"),
                            msg);
            return;
        }
        String username = getFormParameter(msg, "username");
        if (!getParent().isValid(username, getFormParameter(msg, "password"))) {
            getServer()
                    .setJsonResponse(
                            STATUS_BAD_REQUEST,
                            errorJson("invalid_grant", "Invalid username or password"),
                            msg);
            return;
        }
        JSONObject response = new JSONObject();
        response.put("access_token", getParent().getToken(username));
        response.put("token_type", "Bearer");
        response.put("expires_in", 3600);
        getServer().setJsonResponse(response, msg);
    }

    /** The client credentials, from the Basic authorization header or else the form parameters. */
    String[] getClientCredentials(HttpMessage msg) {
        String auth = msg.getRequestHeader().getHeader(HttpHeader.AUTHORIZATION);
        if (auth != null && auth.startsWith(BASIC_PREFIX)) {
            try {
                String decoded =
                        new String(
                                Base64.getDecoder().decode(auth.substring(BASIC_PREFIX.length())),
                                StandardCharsets.UTF_8);
                int colon = decoded.indexOf(':');
                if (colon > 0) {
                    return new String[] {decoded.substring(0, colon), decoded.substring(colon + 1)};
                }
            } catch (IllegalArgumentException e) {
                // Not valid Base64, so there are no credentials.
            }
            return new String[] {null, null};
        }
        return new String[] {
            getFormParameter(msg, "client_id"), getFormParameter(msg, "client_secret")
        };
    }

    private static JSONObject errorJson(String error, String description) {
        JSONObject json = new JSONObject();
        json.put("error", error);
        json.put("error_description", description);
        return json;
    }

    @Override
    public OpenApiSimpleOAuth2Dir getParent() {
        return (OpenApiSimpleOAuth2Dir) super.getParent();
    }
}
