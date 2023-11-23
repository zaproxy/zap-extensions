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

import java.util.HashMap;
import java.util.Map;
import org.apache.commons.lang3.RandomStringUtils;
import org.zaproxy.addon.dev.TestAuthDirectory;
import org.zaproxy.addon.dev.TestProxyServer;

/**
 * A login page which uses one JSON request to login endpoint. The token is returned in a standard
 * field but is submitted with the "Bearer" prefix and in a cookie.
 */
public class JsonMultipleCookiesDir extends TestAuthDirectory {

    private Map<String, String> tempTokens = new HashMap<>();

    public JsonMultipleCookiesDir(TestProxyServer server, String name) {
        super(server, name);
        this.addPage(new JsonMultipleCookiesLoginPage(server));
        this.addPage(new JsonMultipleCookiesSessionPage(server));
        this.addPage(new JsonMultipleCookiesVerificationPage(server));
    }

    public String getTempToken(String username) {
        String token = RandomStringUtils.randomAlphanumeric(32);
        tempTokens.put(token, username);
        return token;
    }

    public String getTempUser(String token) {
        return tempTokens.get(token);
    }
}
