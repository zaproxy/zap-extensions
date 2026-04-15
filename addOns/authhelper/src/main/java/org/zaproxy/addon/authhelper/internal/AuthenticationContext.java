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
package org.zaproxy.addon.authhelper.internal;

import java.util.function.Supplier;

/**
 * Holds state shared across {@link AuthenticationStep} executions within a single authentication
 * attempt.
 *
 * <p>Use {@link #getOrGenerateTotpCode(Supplier)} to obtain the TOTP code for the attempt. The
 * code is generated lazily the first time it is requested, ensuring it is as fresh as possible and
 * is not computed before potentially time-consuming preceding steps run.
 */
public class AuthenticationContext {

    private String cachedTotpCode;

    /**
     * Returns the TOTP code for this authentication attempt, generating it on first call using the
     * supplied {@code generator}.
     *
     * <p>The code is cached after first generation so that all split single-character OTP inputs
     * within the same attempt receive the same value, avoiding mismatches when steps cross a TOTP
     * window boundary.
     *
     * @param generator produces the TOTP code string; called at most once per instance.
     * @return the TOTP code.
     */
    public String getOrGenerateTotpCode(Supplier<String> generator) {
        if (cachedTotpCode == null) {
            cachedTotpCode = generator.get();
        }
        return cachedTotpCode;
    }
}
