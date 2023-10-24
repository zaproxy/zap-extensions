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
package org.zaproxy.addon.dev;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.lang3.RandomStringUtils;

/** A test directory which uses authentication. */
public abstract class TestAuthDirectory extends TestDirectory {

    // These are test credentials, so hardcoding them is fine ;)
    private static final String[][] USERS = {{"test@test.com", "password123"}};

    private Map<String, String> sessions = new HashMap<>();

    public TestAuthDirectory(TestProxyServer server, String name) {
        super(server, name);
    }

    public boolean isValid(String username, String password) {
        return Arrays.stream(USERS)
                .filter(c -> (c[0].equals(username) && c[1].equals(password)))
                .findAny()
                .isPresent();
    }

    public String getToken(String username) {
        String token = RandomStringUtils.randomAlphanumeric(32);
        sessions.put(token, username);
        return token;
    }

    public String getUser(String token) {
        return sessions.get(token);
    }
}
