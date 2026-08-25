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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/**
 * The structured JSON response expected from the LLM at the end of each turn.
 *
 * <p>Example IN_PROGRESS response:
 *
 * <pre>{@code
 * {
 *   "state": "IN_PROGRESS",
 *   "reasoning": "I can see a username field and a domain dropdown. I will fill in the username and select Project1.",
 *   "actions": [
 *     { "type": "SEND_KEYS", "selectors": ["#user", "[name='user']"], "value": "{{username}}" },
 *     { "type": "SELECT",    "selectors": ["#domain", "[name='domain']"], "value": "Project1" },
 *     { "type": "CLICK",     "selectors": ["#next", "button"], "value": null }
 *   ],
 *   "successIndicator": null
 * }
 * }</pre>
 *
 * <p>Example SUCCESS response:
 *
 * <pre>{@code
 * {
 *   "state": "SUCCESS",
 *   "reasoning": "The URL changed to home.html and a greeting is visible.",
 *   "actions": [],
 *   "successIndicator": { "type": "URL_PATTERN", "value": "home.html" }
 * }
 * }</pre>
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AiAuthResponse(
        @JsonProperty("state") AiAuthState state,
        @JsonProperty("reasoning") String reasoning,
        @JsonProperty("actions") List<AiAuthAction> actions,
        @JsonProperty("successIndicator") AiAuthSuccessIndicator successIndicator) {

    /** Returns {@code true} when the LLM has reached a terminal state and the loop should stop. */
    public boolean isTerminal() {
        return state != AiAuthState.IN_PROGRESS;
    }
}
