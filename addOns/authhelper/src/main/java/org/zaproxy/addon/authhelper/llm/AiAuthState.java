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

/** The terminal or intermediate state reported by the LLM at the end of each turn. */
public enum AiAuthState {
    /** More actions are needed — the LLM will provide the next batch. */
    IN_PROGRESS,
    /** Authentication succeeded; a {@code successIndicator} must accompany this state. */
    SUCCESS,
    /** Authentication failed and cannot be recovered (wrong credentials, server error, etc.). */
    FAILURE,
    /** An MFA prompt was detected that the LLM cannot satisfy autonomously. */
    MFA_REQUIRED,
    /** A CAPTCHA was detected; human intervention is required. */
    CAPTCHA_DETECTED
}
