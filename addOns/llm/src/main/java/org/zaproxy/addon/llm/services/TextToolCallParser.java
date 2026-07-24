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
package org.zaproxy.addon.llm.services;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.langchain4j.agent.tool.ToolExecutionRequest;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.lang3.StringUtils;

/**
 * Parses tool-call JSON that some models (notably via Ollama) emit as plain text instead of
 * structured {@code tool_calls}, including when wrapped in prose or markdown fences.
 */
final class TextToolCallParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Set<String> ALLOWED_FIELDS =
            Set.of("name", "arguments", "parameters", "id", "type");
    private static final Pattern FENCED_BLOCK =
            Pattern.compile("```(?:json|JSON)?\\s*\\R([\\s\\S]*?)```");

    private TextToolCallParser() {}

    static Optional<ToolExecutionRequest> tryParse(String text) {
        if (StringUtils.isBlank(text)) {
            return Optional.empty();
        }

        for (String candidate : candidates(text.trim())) {
            Optional<ToolExecutionRequest> parsed = parseObject(candidate);
            if (parsed.isPresent()) {
                return parsed;
            }
        }
        return Optional.empty();
    }

    private static List<String> candidates(String text) {
        List<String> candidates = new ArrayList<>();
        candidates.add(text);

        Matcher fenced = FENCED_BLOCK.matcher(text);
        while (fenced.find()) {
            candidates.add(fenced.group(1).trim());
        }

        // Brace-scan for embedded JSON objects (prose before/after a tool-call payload).
        for (int i = 0; i < text.length(); i++) {
            if (text.charAt(i) != '{') {
                continue;
            }
            int end = findMatchingBrace(text, i);
            if (end > i) {
                candidates.add(text.substring(i, end + 1));
                i = end;
            }
        }
        return candidates;
    }

    private static int findMatchingBrace(String text, int openIndex) {
        int depth = 0;
        boolean inString = false;
        boolean escaped = false;
        for (int i = openIndex; i < text.length(); i++) {
            char ch = text.charAt(i);
            if (inString) {
                if (escaped) {
                    escaped = false;
                } else if (ch == '\\') {
                    escaped = true;
                } else if (ch == '"') {
                    inString = false;
                }
                continue;
            }
            if (ch == '"') {
                inString = true;
            } else if (ch == '{') {
                depth++;
            } else if (ch == '}') {
                depth--;
                if (depth == 0) {
                    return i;
                }
            }
        }
        return -1;
    }

    private static Optional<ToolExecutionRequest> parseObject(String candidate) {
        if (!candidate.startsWith("{") || !candidate.endsWith("}")) {
            return Optional.empty();
        }

        try {
            JsonNode root = MAPPER.readTree(candidate);
            if (!root.isObject() || !hasOnlyAllowedFields(root)) {
                return Optional.empty();
            }

            JsonNode nameNode = root.get("name");
            if (nameNode == null
                    || !nameNode.isTextual()
                    || StringUtils.isBlank(nameNode.asText())) {
                return Optional.empty();
            }

            JsonNode argsNode = root.get("arguments");
            if (argsNode == null) {
                argsNode = root.get("parameters");
            }
            if (argsNode == null) {
                argsNode = MAPPER.createObjectNode();
            }
            if (!argsNode.isObject() && !argsNode.isTextual()) {
                return Optional.empty();
            }

            String arguments =
                    argsNode.isTextual() ? argsNode.asText() : MAPPER.writeValueAsString(argsNode);
            ToolExecutionRequest.Builder builder =
                    ToolExecutionRequest.builder().name(nameNode.asText()).arguments(arguments);
            JsonNode idNode = root.get("id");
            if (idNode != null && idNode.isTextual()) {
                builder.id(idNode.asText());
            }
            return Optional.of(builder.build());
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    private static boolean hasOnlyAllowedFields(JsonNode root) {
        Iterator<String> fields = root.fieldNames();
        while (fields.hasNext()) {
            if (!ALLOWED_FIELDS.contains(fields.next())) {
                return false;
            }
        }
        return true;
    }
}
