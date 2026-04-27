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
     * Tracks how many split-OTP ({@code maxlength="1"}) TOTP_FIELD steps have executed in this
     * attempt.
     *
     * <ul>
     *   <li>Index 0 — first step: use {@code fillSplitOtpFields} to auto-fill all boxes at once
     *       (single-step YAML) or fill all boxes before individual steps take over.
     *   <li>Index 1-N — subsequent per-digit steps: fill only the character at this index into the
     *       specific targeted box (multi-step YAML, one step per digit).
     * </ul>
     */
    private int splitOtpCharIndex = 0;

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

    /**
     * Returns the current split-OTP character index and increments it for the next call.
     *
     * <p>Called once per TOTP_FIELD step that targets a {@code maxlength="1"} input:
     *
     * <ul>
     *   <li>Returns 0 on the first call — caller should use {@code fillSplitOtpFields} to fill all
     *       boxes at once. This covers both the single-step YAML case and the first step of a
     *       multi-step YAML.
     *   <li>Returns 1-N on subsequent calls — caller should fill only {@code
     *       totpCode.charAt(index)} into its specific box. This covers the remaining steps of a
     *       multi-step YAML where each step targets one digit box.
     * </ul>
     *
     * @return the zero-based index of this split-OTP step within the current attempt.
     */
    public int nextSplitOtpCharIndex() {
        return splitOtpCharIndex++;
    }

    /**
     * Returns the current split-OTP character index without incrementing it.
     *
     * <p>Used to decide before the element lookup whether this TOTP_FIELD step should
     * be skipped entirely (charIndex &gt; 0 means step 0 already filled all boxes).
     *
     * @return the zero-based index of the next split-OTP step.
     */
    public int peekSplitOtpCharIndex() {
        return splitOtpCharIndex;
    }
}
