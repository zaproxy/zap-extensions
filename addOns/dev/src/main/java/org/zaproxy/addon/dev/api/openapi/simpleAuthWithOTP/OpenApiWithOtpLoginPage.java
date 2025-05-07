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
package org.zaproxy.addon.dev.api.openapi.simpleAuthWithOTP;

import net.sf.json.JSONException;
import net.sf.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.dev.TestPage;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

public class OpenApiWithOtpLoginPage extends TestPage {

    private static final Logger LOGGER = LogManager.getLogger(OpenApiWithOtpLoginPage.class);

    public OpenApiWithOtpLoginPage(TestProxyServer server) {
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
        if (getParent().isValid(username, password)) {

            response.put("result", "OK");
            String token = getParent().getToken(username);
            getParent().setUser(token, username);
            String totp = getParent().generateAndStoreTotp(token);
            response.put("accesstoken", token);
            response.put("totp", totp);

        } else {
            response.put("result", "FAIL");
        }
        this.getServer().setJsonResponse(response, msg);
    }

    @Override
    public OpenApiWithOtpSimpleAuthDir getParent() {
        return (OpenApiWithOtpSimpleAuthDir) super.getParent();
    }
}
