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

/**
 * A form element extracted from the current page and included in the LLM turn payload. Gives the
 * LLM enough context to identify each field and generate reliable selectors.
 */
public record AiAuthInputElement(
        @JsonProperty("tag") String tag,
        @JsonProperty("type") String type,
        @JsonProperty("id") String id,
        @JsonProperty("name") String name,
        @JsonProperty("label") String label,
        @JsonProperty("placeholder") String placeholder,
        @JsonProperty("value") String value,
        @JsonProperty("options") List<String> options,
        @JsonProperty("visible") boolean visible) {}
