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

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * The outcome of a single action that was executed in a previous turn. Included in the next turn's
 * payload so the LLM knows what was tried and whether it worked.
 */
public record AiAuthActionResult(
        @JsonProperty("type") AiAuthActionType type,
        @JsonProperty("usedSelector") String usedSelector,
        @JsonProperty("value") String value,
        @JsonProperty("success") boolean success,
        @JsonProperty("error") String error) {

    /** Convenience factory for a successful action execution. */
    public static AiAuthActionResult ok(AiAuthActionType type, String usedSelector, String value) {
        return new AiAuthActionResult(type, usedSelector, value, true, null);
    }

    /** Convenience factory for a failed action execution. */
    public static AiAuthActionResult failed(AiAuthActionType type, String error) {
        return new AiAuthActionResult(type, null, null, false, error);
    }
}
