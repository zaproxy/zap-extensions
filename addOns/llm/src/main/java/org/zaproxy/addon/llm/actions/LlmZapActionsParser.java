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
package org.zaproxy.addon.llm.actions;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.apache.commons.lang3.StringUtils;

public class LlmZapActionsParser {

    public static final String ACTIONS_BEGIN = "BEGIN_ZAP_ACTIONS";
    public static final String ACTIONS_END = "END_ZAP_ACTIONS";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public LlmZapActionsParseResult parse(String assistantText) {
        if (StringUtils.isBlank(assistantText)) {
            return new LlmZapActionsParseResult(Collections.emptyList(), Collections.emptyList());
        }

        String json = extractActionsJson(assistantText);
        if (StringUtils.isBlank(json)) {
            return new LlmZapActionsParseResult(Collections.emptyList(), List.of());
        }

        List<String> warnings = new ArrayList<>();
        List<LlmZapAction> actions = new ArrayList<>();
        try {
            JsonNode root = MAPPER.readTree(json);
            JsonNode actionsNode = root.path("actions");
            if (!actionsNode.isArray()) {
                warnings.add("Missing or invalid 'actions' array.");
                return new LlmZapActionsParseResult(Collections.emptyList(), warnings);
            }

            for (JsonNode actionNode : actionsNode) {
                String actionId = textOrNull(actionNode, "action");
                LlmZapActionType type = LlmZapActionType.fromId(actionId);
                if (type == null) {
                    warnings.add("Unsupported action: " + StringUtils.defaultString(actionId));
                    continue;
                }
                int historyId = actionNode.path("history_id").asInt(-1);
                if (historyId <= 0) {
                    warnings.add("Missing or invalid history_id for action: " + actionId);
                    continue;
                }

                String note = textOrNull(actionNode, "note");
                List<String> tags = new ArrayList<>();
                if (actionNode.has("tags") && actionNode.get("tags").isArray()) {
                    for (JsonNode t : actionNode.get("tags")) {
                        String tag = StringUtils.trimToEmpty(t.asText());
                        if (!tag.isEmpty()) {
                            tags.add(tag);
                        }
                    }
                }

                actions.add(new LlmZapAction(type, historyId, note, tags));
            }
        } catch (Exception e) {
            warnings.add("Failed to parse actions JSON: " + e.getMessage());
            return new LlmZapActionsParseResult(Collections.emptyList(), warnings);
        }

        return new LlmZapActionsParseResult(actions, warnings);
    }

    private static String extractActionsJson(String assistantText) {
        int begin = assistantText.indexOf(ACTIONS_BEGIN);
        int end = assistantText.indexOf(ACTIONS_END);
        if (begin >= 0 && end > begin) {
            return assistantText.substring(begin + ACTIONS_BEGIN.length(), end).trim();
        }

        String trimmed = assistantText.trim();
        if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
            return trimmed;
        }
        return null;
    }

    private static String textOrNull(JsonNode node, String field) {
        JsonNode v = node.get(field);
        if (v == null || v.isNull()) {
            return null;
        }
        String text = v.asText();
        return StringUtils.isBlank(text) ? null : text;
    }
}

