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

import java.util.HashMap;
import java.util.Map;
import org.zaproxy.addon.dev.TestAuthDirectory;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.dev.auth.totp.TestTotp;
import org.zaproxy.addon.dev.auth.totp.simpleAuthWithOTP.OpenApiWithOtpLoginPage;
import org.zaproxy.addon.dev.auth.totp.simpleAuthWithOTP.OpenApiWithOtpTestApiPage;
import org.zaproxy.addon.dev.auth.totp.simpleAuthWithOTP.OpenApiWithOtpVerificationPage;

/**
 * A directory which contains an OpenAPI spec. The spec is available unauthenticated but the
 * endpoint it describes can only be accessed when a valid Authentication header is supplied. The
 * login page uses one JSON request to login endpoint. The token is returned in a standard field.
 */
public class OpenApiWithReplayOtpSimpleAuthDir extends TestAuthDirectory {
    private Map<String, Boolean> verifiedTokens = new HashMap<>();
    private Map<String, String> tokenToUserMap = new HashMap<>();
    private final Map<String, UsedOtpInfo> usedTotpCodes = new HashMap<>();

    private static class UsedOtpInfo {
        String otpCode;
        long usedAtMillis;

        UsedOtpInfo(String otpCode, long usedAtMillis) {
            this.otpCode = otpCode;
            this.usedAtMillis = usedAtMillis;
        }
    }

    public OpenApiWithReplayOtpSimpleAuthDir(TestProxyServer server, String name) {
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
        String code = TestTotp.generateCurrentCode();
        return code;
    }

    public boolean validateTotp(String token, String code) {
        UsedOtpInfo lastUsed = usedTotpCodes.get(token);

        if (lastUsed != null) {
            if (lastUsed.otpCode.equals(code)) {
                long now = System.currentTimeMillis();
                long elapsed = now - lastUsed.usedAtMillis;
                if (elapsed < 30_000) {
                    return false;
                }
            }
        }

        boolean valid = TestTotp.isCodeValid(code);
        if (valid) {
            usedTotpCodes.put(token, new UsedOtpInfo(code, System.currentTimeMillis()));
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
