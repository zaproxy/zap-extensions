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
package org.zaproxy.zap.extension.llmheader;

import java.util.ArrayList;
import java.util.List;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

public class LLMResultParser {

    public static List<LLMIssue> parse(String json) {
        List<LLMIssue> issues = new ArrayList<>();
        try {
            // Handle potential markdown code blocks if the LLM returns them
            String cleanJson = json;
            if (json.contains("```json")) {
                cleanJson = json.substring(json.indexOf("```json") + 7);
                if (cleanJson.contains("```")) {
                    cleanJson = cleanJson.substring(0, cleanJson.indexOf("```"));
                }
            } else if (json.contains("```")) {
                cleanJson = json.substring(json.indexOf("```") + 3);
                if (cleanJson.contains("```")) {
                    cleanJson = cleanJson.substring(0, cleanJson.indexOf("```"));
                }
            }
            cleanJson = cleanJson.trim();

            if (cleanJson.startsWith("[")) {
                JSONArray array = JSONArray.fromObject(cleanJson);
                for (int i = 0; i < array.size(); i++) {
                    JSONObject obj = array.getJSONObject(i);
                    issues.add(
                            new LLMIssue(
                                    obj.optString("issue", "Unknown Issue"),
                                    obj.optString("severity", "Low"),
                                    obj.optString("confidence", "Low"),
                                    obj.optString("recommendation", "No recommendation provided")));
                }
            }
        } catch (Exception e) {
            // Log error or return empty list
        }
        return issues;
    }
}
