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
package org.zaproxy.addon.dev.auth.totp.simpleAuthTotpReplayVuln;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.zaproxy.addon.dev.TestAuthDirectory;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.dev.auth.totp.TestTotp;

/**
 * A directory which contains an OpenAPI spec. The spec is available unauthenticated but the
 * endpoint it describes can only be accessed when a valid Authentication header is supplied. The
 * login page uses one JSON request to login endpoint. The token is returned in a standard field.
 */
public class OpenApiWithReplayOtpSimpleAuthDir extends TestAuthDirectory {
    private Map<String, Boolean> verifiedTokens = new HashMap<>();
    private Map<String, String> tokenToUserMap = new HashMap<>();
    private Map<String, Set<String>> acceptedTotpsPerUser = new HashMap<>();

    public OpenApiWithReplayOtpSimpleAuthDir(TestProxyServer server, String name) {
        super(server, name);
        this.addPage(new OpenApiWithReplayOtpLoginPage(server));
        this.addPage(new OpenApiWithReplayOtpVerificationPage(server));
        this.addPage(new OpenApiWithReplayOtpTestApiPage(server));
    }

    public void markTokenVerified(String token) {
        verifiedTokens.put(token, true);
    }

    public boolean isTokenVerified(String token) {
        return verifiedTokens.getOrDefault(token, false);
    }

    public String generateAndStoreTotp(String token) {
        String user = tokenToUserMap.get(token);
        if (user == null) {
            return "ERROR";
        }

        String code = TestTotp.generateCurrentCode();

        acceptedTotpsPerUser.computeIfAbsent(user, k -> new HashSet<>()).add(code);

        return code;
    }

    public boolean validateTotp(String token, String code) {
        String user = tokenToUserMap.get(token);
        if (user == null) {
            return false;
        }

        Set<String> acceptedCodes = acceptedTotpsPerUser.getOrDefault(user, Collections.emptySet());
        return acceptedCodes.contains(code);
    }

    public void setUser(String token, String user) {
        tokenToUserMap.put(token, user);
    }

    @Override
    public String getUser(String token) {
        return tokenToUserMap.get(token);
    }
}
