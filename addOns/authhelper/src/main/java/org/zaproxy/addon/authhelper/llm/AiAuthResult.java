/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.authhelper.llm;

/**
 * The outcome of a single run of {@link AiAuthScriptGenerator}. Carries enough information for the
 * caller to decide what to do next and, in later phases, to build a Zest replay script.
 */
public record AiAuthResult(
        boolean success,
        AiAuthState finalState,
        String reasoning,
        AiAuthSuccessIndicator successIndicator) {

    /** Convenience factory for a clean failure with a diagnostic message. */
    public static AiAuthResult failure(String reason) {
        return new AiAuthResult(false, AiAuthState.FAILURE, reason, null);
    }
}
