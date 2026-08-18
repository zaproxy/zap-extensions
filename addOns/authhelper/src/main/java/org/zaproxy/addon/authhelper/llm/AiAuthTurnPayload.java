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
import java.util.List;
import java.util.Map;

/**
 * The payload sent to the LLM at the start of each turn. Describes the current page state and the
 * outcomes of any actions taken in the previous turn.
 *
 * <p>Credentials are passed as placeholder tokens ({@link #USERNAME_PLACEHOLDER}, {@link
 * #PASSWORD_PLACEHOLDER}) so that real credentials are never transmitted to the LLM. The caller
 * must substitute the real values when executing the actions.
 *
 * <p>Example first-turn payload:
 *
 * <pre>{@code
 * {
 *   "step": 1,
 *   "url": "http://localhost:8080/auth/multi-step-auth/",
 *   "pageTitle": "Login",
 *   "inputElements": [
 *     { "tag": "input", "type": "email", "id": "user",   "name": "user",   "label": "Username:", "placeholder": "", "value": "", "options": null, "visible": true },
 *     { "tag": "select","type": null,    "id": "domain", "name": "domain", "label": "Domain:",   "placeholder": "", "value": "", "options": ["alpha.example.com","beta.example.com","Project1","Project2"], "visible": true }
 *   ],
 *   "previousActions": [],
 *   "credentials": { "username": "{{username}}", "password": "{{password}}" },
 *   "userHint": "The domain pulldown needs to be set to Project1"
 * }
 * }</pre>
 */
public record AiAuthTurnPayload(
        @JsonProperty("step") int step,
        @JsonProperty("url") String url,
        @JsonProperty("pageTitle") String pageTitle,
        @JsonProperty("inputElements") List<AiAuthInputElement> inputElements,
        @JsonProperty("previousActions") List<AiAuthActionResult> previousActions,
        @JsonProperty("credentials") Map<String, String> credentials,
        @JsonProperty("userHint") String userHint,
        @JsonProperty("visibleText") String visibleText) {

    /** Placeholder token used in the credentials map for the username. */
    public static final String USERNAME_PLACEHOLDER = "{{username}}";

    /** Placeholder token used in the credentials map for the password. */
    public static final String PASSWORD_PLACEHOLDER = "{{password}}";
}
