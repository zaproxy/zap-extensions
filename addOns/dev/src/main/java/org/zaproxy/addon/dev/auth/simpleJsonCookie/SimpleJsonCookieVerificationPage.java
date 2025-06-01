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

import java.net.HttpCookie;
import java.util.List;
import net.sf.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.dev.TestPage;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

public class SimpleJsonCookieVerificationPage extends TestPage {

    private static final Logger LOGGER =
            LogManager.getLogger(SimpleJsonCookieVerificationPage.class);

    public SimpleJsonCookieVerificationPage(TestProxyServer server) {
        super(server, "user");
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
        String cookie = null;
        List<HttpCookie> cookieList = msg.getRequestHeader().getHttpCookies();
        for (HttpCookie hc : cookieList) {
            if ("sid".equals(hc.getName())) {
                cookie = hc.getValue();
            }
        }
        String user = getParent().getUser(cookie);
        LOGGER.debug("Token: {} user: {}", cookie, user);

        JSONObject response = new JSONObject();
        String status = TestProxyServer.STATUS_FORBIDDEN;
        if (cookie == null) {
            response.put("result", "FAIL (no cookie)");
        } else if (user != null) {
            response.put("result", "OK");
            response.put("user", user);
            status = TestProxyServer.STATUS_OK;
        } else {
            response.put("result", "FAIL");
        }
        this.getServer().setJsonResponse(status, response, msg);
    }

    @Override
    public SimpleJsonCookieDir getParent() {
        return (SimpleJsonCookieDir) super.getParent();
    }
}
