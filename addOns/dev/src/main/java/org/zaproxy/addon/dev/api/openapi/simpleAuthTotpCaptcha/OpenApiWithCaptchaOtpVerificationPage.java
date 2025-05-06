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
package org.zaproxy.addon.dev.api.openapi.simpleAuthTotpCaptcha;

import java.util.concurrent.ConcurrentHashMap;
import net.sf.json.JSONException;
import net.sf.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.dev.TestPage;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

public class OpenApiWithCaptchaOtpVerificationPage extends TestPage {

    private static final Logger LOGGER =
            LogManager.getLogger(OpenApiWithCaptchaOtpVerificationPage.class);
    private static final ConcurrentHashMap<String, String> captchaStore = new ConcurrentHashMap<>();

    public OpenApiWithCaptchaOtpVerificationPage(TestProxyServer server) {
        super(server, "user");
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
        String method = msg.getRequestHeader().getMethod();
        String token = msg.getRequestHeader().getHeader(HttpHeader.AUTHORIZATION);
        String user = getParent().getUser(token);
        JSONObject response = new JSONObject();

        if ("GET".equalsIgnoreCase(method)) {
            if (user != null && getParent().isTokenVerified(token)) {
                response.put("result", "OK");
                response.put("user", user);
            } else {
                response.put("result", "FAIL");
            }
            this.getServer().setJsonResponse(response, msg);
            return;
        }

        String totp = null;
        String captcha = null;

        if (msg.getRequestHeader().hasContentType("json")) {
            String postData = msg.getRequestBody().toString();
            JSONObject jsonObject;
            try {
                jsonObject = JSONObject.fromObject(postData);
                totp = jsonObject.getString("code");
                captcha = jsonObject.getString("captcha");
            } catch (JSONException e) {
                LOGGER.debug("Unable to parse as JSON: {}", postData, e);
            }
        }

        // Validate CAPTCHA
        String expectedCaptcha = captchaStore.remove(token);
        boolean isCaptchaValid = expectedCaptcha != null && expectedCaptcha.equals(captcha);

        LOGGER.debug(
                "Token: {} user: {} TOTP: {} CAPTCHA: {} Expected CAPTCHA: {}",
                token,
                user,
                totp,
                captcha,
                expectedCaptcha);

        if (user != null && totp != null && totp.equals("123456") && isCaptchaValid) {
            response.put("result", "OK");
            response.put("user", user);
            getParent().markTokenVerified(token);
        } else {
            response.put("result", "FAIL");
        }

        // Generate a new CAPTCHA for the next request
        String newCaptcha = "captcha" + (int) (Math.random() * 10000);
        captchaStore.put(token, newCaptcha);
        response.put("newCaptcha", newCaptcha);

        this.getServer().setJsonResponse(response, msg);
    }

    @Override
    public OpenApiWithCaptchaOtpSimpleAuthDir getParent() {
        return (OpenApiWithCaptchaOtpSimpleAuthDir) super.getParent();
    }
}
