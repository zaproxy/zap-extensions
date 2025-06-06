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
package org.zaproxy.addon.dev.auth.totp.simpleAuthWithOTP;

import java.util.HashMap;
import java.util.Map;
import org.zaproxy.addon.dev.TestAuthDirectory;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.dev.auth.totp.TestTotp;

/**
 * A directory which contains an OpenAPI spec. The spec is available unauthenticated but the
 * endpoint it describes can only be accessed when a valid Authentication header is supplied. The
 * login page uses one JSON request to login endpoint. The token is returned in a standard field.
 */
public class OpenApiWithOtpSimpleAuthDir extends TestAuthDirectory {
    private Map<String, Boolean> verifiedTokens = new HashMap<>();
    private final Map<String, String> tokenToUserMap = new HashMap<>();
    private final Map<String, UsedOtpInfo> usedTotpCodes = new HashMap<>();
    private final Map<String, String> lastTotpPerUser = new HashMap<>();

    private static class UsedOtpInfo {
        String otpCode;

        UsedOtpInfo(String otpCode) {
            this.otpCode = otpCode;
        }
    }

    public OpenApiWithOtpSimpleAuthDir(TestProxyServer server, String name) {
        super(server, name);
        this.addPage(new OpenApiWithOtpLoginPage(server));
        this.addPage(new OpenApiWithOtpVerificationPage(server));
        this.addPage(new OpenApiWithOtpTestApiPage(server));
    }

    public void markTokenVerified(String token) {
        verifiedTokens.put(token, true);
    }

    public boolean isTokenVerified(String token) {
        return verifiedTokens.getOrDefault(token, false);
    }

    public String generateAndStoreTotp(String token) {
        String username = tokenToUserMap.get(token);
        if (username == null) {
            return "ERROR";
        }

        String newCode = TestTotp.generateCurrentCode();
        String lastCode = lastTotpPerUser.get(username);

        if (newCode.equals(lastCode)) {
            lastTotpPerUser.put(username, "198755");
            return "198755";
        }

        lastTotpPerUser.put(username, newCode);
        return newCode;
    }

    public boolean validateTotp(String token, String code) {
        String username = tokenToUserMap.get(token);
        if (username == null) {
            return false;
        }

        UsedOtpInfo lastUsed = usedTotpCodes.get(username);
        if (lastUsed != null && lastUsed.otpCode.equals(code)) {
            return false; // Replay for same user
        }

        boolean valid = (TestTotp.isCodeValid(code) || code.equals("198755"));
        if (valid) {
            usedTotpCodes.put(username, new UsedOtpInfo(code));
        }

        return valid;
    }

    public void setUser(String token, String user) {
        tokenToUserMap.put(token, user);
    }

    @Override
    public String getUser(String token) {
        return tokenToUserMap.get(token);
    }
}
