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

import net.sf.json.JSONObject;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.dev.TestPage;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

/** The endpoint described by the spec, it requires a bearer token from the token endpoint. */
public class OpenApiOAuth2TestApiPage extends TestPage {

    static final String BEARER_PREFIX = "Bearer ";

    public OpenApiOAuth2TestApiPage(TestProxyServer server) {
        super(server, "test-api");
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
        String auth = msg.getRequestHeader().getHeader(HttpHeader.AUTHORIZATION);
        String token =
                auth != null && auth.startsWith(BEARER_PREFIX)
                        ? auth.substring(BEARER_PREFIX.length())
                        : null;

        JSONObject response = new JSONObject();
        if (getParent().getUser(token) != null) {
            response.put("result", "Success");
            this.getServer().setJsonResponse(TestProxyServer.STATUS_OK, response, msg);
        } else {
            response.put("result", "FAIL");
            this.getServer()
                    .setJsonResponse(OpenApiSimpleOAuth2Dir.STATUS_UNAUTHORIZED, response, msg);
        }
    }

    @Override
    public OpenApiSimpleOAuth2Dir getParent() {
        return (OpenApiSimpleOAuth2Dir) super.getParent();
    }
}
