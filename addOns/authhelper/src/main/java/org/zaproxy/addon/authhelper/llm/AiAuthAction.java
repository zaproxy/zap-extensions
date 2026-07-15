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
 * A single browser action returned by the LLM. {@code selectors} is an ordered list of alternatives
 * — ZAP tries them in order and uses the first one that resolves to an element, preferring stable
 * identifiers (id, name) over fragile structural ones (XPath).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AiAuthAction(
        @JsonProperty("type") AiAuthActionType type,
        @JsonProperty("selectors") List<String> selectors,
        @JsonProperty("value") String value) {}
