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
package org.zaproxy.addon.dev.auth.jsonMultipleCookies;

import java.net.HttpCookie;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;
import net.sf.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.dev.TestPage;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

public class JsonMultipleCookiesSessionPage extends TestPage {

    private static final Logger LOGGER = LogManager.getLogger(JsonMultipleCookiesSessionPage.class);

    public JsonMultipleCookiesSessionPage(TestProxyServer server) {
        super(server, "session");
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
        String cookie = null;
        List<HttpCookie> cookieList = msg.getRequestHeader().getHttpCookies();
        for (HttpCookie hc : cookieList) {
            if (hc.getName().equals("temp")) {
                cookie = hc.getValue();
            }
        }
        String user = getParent().getTempUser(cookie);
        LOGGER.debug("Temp token: {} user: {}", cookie, user);

        JSONObject response = new JSONObject();
        String token = null;
        String status = TestProxyServer.STATUS_FORBIDDEN;
        if (cookie == null) {
            response.put("result", "FAIL (no temp cookie)");
        } else if (user != null) {
            token = getParent().getToken(user);
            response.put("result", "OK");
            status = TestProxyServer.STATUS_OK;
        } else {
            response.put("result", "FAIL");
        }
        this.getServer().setJsonResponse(status, response, msg);
        if (token != null) {
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
            msg.getResponseHeader()
                    .addHeader(
                            HttpHeader.SET_COOKIE,
                            "temp=; Expires: "
                                    + sdf.format(new Date(System.currentTimeMillis() - 1000)));
            msg.getResponseHeader()
                    .addHeader(HttpHeader.SET_COOKIE, "sid=" + token + "; SameSite=Strict");
        }
    }

    @Override
    public JsonMultipleCookiesDir getParent() {
        return (JsonMultipleCookiesDir) super.getParent();
    }
}
