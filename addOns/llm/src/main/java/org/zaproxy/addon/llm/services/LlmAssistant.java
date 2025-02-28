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

import dev.langchain4j.service.SystemMessage;
import dev.langchain4j.service.UserMessage;
import dev.langchain4j.service.V;
import org.zaproxy.addon.llm.communication.Confidence;
import org.zaproxy.addon.llm.communication.HttpRequestList;

public interface LlmAssistant {
    @UserMessage(
            "Given the following OpenAPI definition, generate a list of chained HTTP requests to simulate a real world interaction : {{swagger}} ")
    HttpRequestList extractHttpRequests(String swagger);

    @UserMessage(
            "As a software architect, and based on your previous answer, generate other potential missing endpoints that are not mentioned in the swagger file. For example, if there is GET /product/1, suggest DELETE /product/1 if it's not mentioned")
    HttpRequestList complete();

    @SystemMessage(
            "You are a web application security expert reviewing potential false positives. Answer only in JSON.")
    @UserMessage(
            "Your task is to review the following finding from ZAP (Zed Attack Proxy).\n"
                    + "The confidence level is a pull down field which allows you to specify how confident you are in the validity of the finding : \n"
                    + "- 0 if it's False Positive\n"
                    + "- 1 if it's Low\n"
                    + "- 2 if it's Medium\n"
                    + "- 3 if it's High\n"
                    + "\n"
                    + "The alert is described as follows : {{description}}\n"
                    + "\n"
                    + "As evidence, the HTTP response contains :\n"
                    + "---\n"
                    + "{{evidence}}\n"
                    + "---\n"
                    + "Provide a short consistent explanation of the new score.\n")
    Confidence review(@V("description") String description, @V("evidence") String evidence);
}
