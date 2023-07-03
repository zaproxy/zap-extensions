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
package org.zaproxy.addon.dev.auth.simpleJsonCookie;

import net.sf.json.JSONException;
import net.sf.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.dev.TestPage;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

public class SimpleJsonCookieLoginPage extends TestPage {

    private static final Logger LOGGER = LogManager.getLogger(SimpleJsonCookieLoginPage.class);

    public SimpleJsonCookieLoginPage(TestProxyServer server) {
        super(server, "login");
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
        String username = null;
        String password = null;

        if (msg.getRequestHeader().hasContentType("json")) {
            String postData = msg.getRequestBody().toString();
            JSONObject jsonObject;
            try {
                jsonObject = JSONObject.fromObject(postData);
                username = jsonObject.getString("user");
                password = jsonObject.getString("password");
            } catch (JSONException e) {
                LOGGER.debug("Unable to parse as JSON: {}", postData, e);
            }
        }

        JSONObject response = new JSONObject();
        String token = null;
        if (getParent().isValid(username, password)) {
            token = getParent().getToken(username);
            response.put("result", "OK");
        } else {
            response.put("result", "FAIL");
        }
        this.getServer().setJsonResponse(response, msg);
        if (token != null) {
            msg.getResponseHeader()
                    .addHeader(HttpHeader.SET_COOKIE, "sid=" + token + "; SameSite=Strict");
        }
        // This is not actually used anywhere
        msg.getResponseHeader().addHeader(HttpHeader.SET_COOKIE, "_random=blahblah");
    }

    @Override
    public SimpleJsonCookieDir getParent() {
        return (SimpleJsonCookieDir) super.getParent();
    }
}
