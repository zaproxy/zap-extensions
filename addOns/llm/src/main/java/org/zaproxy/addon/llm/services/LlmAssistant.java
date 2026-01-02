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
package org.zaproxy.addon.llm.services;

import dev.langchain4j.service.UserMessage;
import org.zaproxy.addon.llm.communication.HttpRequestList;

public interface LlmAssistant {
    @UserMessage(
            "Given the following OpenAPI definition, generate a list of chained HTTP requests to simulate a real world interaction : {{openapi}} ")
    HttpRequestList extractHttpRequests(String openapi);

    @UserMessage(
            "As a software architect, and based on your previous answer, generate other potential missing endpoints that are not mentioned in the OpenAPI file. For example, if there is GET /product/1, suggest DELETE /product/1 if it's not mentioned")
    HttpRequestList complete();
}
