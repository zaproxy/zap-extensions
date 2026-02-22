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

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonFactoryBuilder;
import com.fasterxml.jackson.core.json.JsonReadFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import org.apache.commons.lang3.StringUtils;
import org.zaproxy.zap.model.HttpMessageLocation;

public class LlmZapActionsParser {

    public static final String ACTIONS_BEGIN = "BEGIN_ZAP_ACTIONS";
    public static final String ACTIONS_END = "END_ZAP_ACTIONS";

    private static final ObjectMapper MAPPER = new ObjectMapper(buildJsonFactory());

    private static JsonFactory buildJsonFactory() {
        return new JsonFactoryBuilder()
                .enable(JsonReadFeature.ALLOW_JAVA_COMMENTS)
                .enable(JsonReadFeature.ALLOW_SINGLE_QUOTES)
                .enable(JsonReadFeature.ALLOW_TRAILING_COMMA)
                .build();
    }

    public LlmZapActionsParseResult parse(String assistantText) {
        if (StringUtils.isBlank(assistantText)) {
            return new LlmZapActionsParseResult(
                    Collections.emptyList(), Collections.emptyList(), null, null);
        }

        String json = extractActionsJson(assistantText);
        if (StringUtils.isBlank(json)) {
            return new LlmZapActionsParseResult(
                    Collections.emptyList(),
                    List.of("No actions JSON found in the assistant text."),
                    null,
                    null);
        }

        List<String> warnings = new ArrayList<>();
        List<LlmZapAction> actions = new ArrayList<>();
        JsonNode root = null;
        try {
            root = MAPPER.readTree(json);
            List<JsonNode> actionNodes = extractActionNodes(root, warnings);
            if (actionNodes.isEmpty()) {
                return new LlmZapActionsParseResult(Collections.emptyList(), warnings, root, json);
            }

            for (JsonNode actionNode : actionNodes) {
                String actionId = parseActionId(actionNode);
                LlmZapActionType type = LlmZapActionType.fromId(actionId);
                if (type == null) {
                    warnings.add(buildUnsupportedActionWarning(actionNode, actionId));
                    continue;
                }
                int historyId = actionNode.path("history_id").asInt(-1);

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

                HttpMessageLocation.Location location =
                        parseLocation(textOrNull(actionNode, "location"));
                int start = actionNode.path("start").asInt(-1);
                int end = actionNode.path("end").asInt(-1);

                // Some models nest selection details under "selection" rather than on the action
                // object.
                JsonNode selectionNode = actionNode.get("selection");
                String selectionText = null;
                if (selectionNode != null && selectionNode.isObject()) {
                    if (location == null) {
                        location = parseLocation(textOrNull(selectionNode, "location"));
                    }
                    if (start < 0) {
                        start = selectionNode.path("start").asInt(-1);
                    }
                    if (end < 0) {
                        end = selectionNode.path("end").asInt(-1);
                    }
                    selectionText = textOrNull(selectionNode, "text");
                }

                // Some models use "insertion_point" instead of (location/start/end + payload).
                JsonNode insertionPointNode = actionNode.get("insertion_point");
                if (insertionPointNode == null) {
                    insertionPointNode = actionNode.get("insertionPoint");
                }
                String insertionPayload = null;
                if (insertionPointNode != null && insertionPointNode.isObject()) {
                    if (location == null) {
                        location = parseLocation(textOrNull(insertionPointNode, "location"));
                    }
                    if (start < 0) {
                        start = insertionPointNode.path("start").asInt(-1);
                    }
                    if (end < 0) {
                        end = insertionPointNode.path("end").asInt(-1);
                    }
                    insertionPayload = textOrNull(insertionPointNode, "payload");
                }
                String payload = textOrNull(actionNode, "payload");
                List<String> payloads = extractPayloadList(actionNode.get("payloads"));

                // Some models omit "payload" for requester actions but include "payloads" or
                // "selection.text".
                if (StringUtils.isBlank(payload)
                        && (type == LlmZapActionType.OPEN_REQUESTER_DIALOG
                                || type == LlmZapActionType.OPEN_REQUESTER_TAB)) {
                    if (!payloads.isEmpty()) {
                        payload = payloads.get(0);
                    } else if (StringUtils.isNotBlank(insertionPayload)) {
                        payload = insertionPayload;
                    } else if (StringUtils.isNotBlank(selectionText)) {
                        payload = selectionText;
                    }
                }

                // Some models provide a single payload string for fuzzer.
                if ((payloads == null || payloads.isEmpty())
                        && type == LlmZapActionType.OPEN_FUZZER
                        && StringUtils.isNotBlank(payload)) {
                    payloads = List.of(payload);
                    payload = null;
                }

                // Some models use alternate fields for fuzzer payload lists.
                if ((payloads == null || payloads.isEmpty())
                        && type == LlmZapActionType.OPEN_FUZZER) {
                    payloads =
                            firstNonEmptyPayloadList(
                                    payloads,
                                    extractPayloadList(actionNode.get("payload_list")),
                                    extractPayloadList(actionNode.get("payloadList")),
                                    extractPayloadList(actionNode.get("payload_values")),
                                    extractPayloadList(actionNode.get("payloadValues")),
                                    extractPayloadList(actionNode.get("values")),
                                    extractPayloadList(actionNode.get("items")));
                }

                // Last resort: use the selected text as a single payload.
                if ((payloads == null || payloads.isEmpty())
                        && type == LlmZapActionType.OPEN_FUZZER
                        && StringUtils.isNotBlank(selectionText)) {
                    payloads = List.of(selectionText);
                }

                LlmZapRequestData request = null;
                JsonNode requestNode = actionNode.get("request");
                if (requestNode != null && requestNode.isObject()) {
                    String header = textOrNull(requestNode, "header");
                    String body = textOrNull(requestNode, "body");
                    if (StringUtils.isNotBlank(header) || StringUtils.isNotBlank(body)) {
                        request = new LlmZapRequestData(header, body);
                    }
                }

                String validationIssue =
                        validate(
                                type, historyId, note, tags, location, start, end, payload,
                                payloads, request);
                if (validationIssue != null) {
                    warnings.add(validationIssue);
                    continue;
                }

                actions.add(
                        new LlmZapAction(
                                type, historyId, note, tags, location, start, end, payload,
                                payloads, request));
            }
        } catch (Exception e) {
            warnings.add("Failed to parse actions JSON: " + e.getMessage());
            return new LlmZapActionsParseResult(Collections.emptyList(), warnings, null, json);
        }

        return new LlmZapActionsParseResult(actions, warnings, root, json);
    }

    private static List<JsonNode> extractActionNodes(JsonNode root, List<String> warnings) {
        if (root == null || root.isNull()) {
            warnings.add("Missing actions JSON.");
            return Collections.emptyList();
        }

        if (root.isArray()) {
            List<JsonNode> nodes = new ArrayList<>();
            root.forEach(nodes::add);
            return nodes;
        }

        if (root.isObject()) {
            JsonNode actionsNode = root.get("actions");
            if (actionsNode != null && actionsNode.isArray()) {
                List<JsonNode> nodes = new ArrayList<>();
                actionsNode.forEach(nodes::add);
                return nodes;
            }

            // Allow a single action object (models sometimes omit the wrapper array).
            if (parseActionId(root) != null) {
                return List.of(root);
            }

            warnings.add(
                    "Missing or invalid 'actions' array. Expected {\"actions\": [...]} or a single action object.");
            return Collections.emptyList();
        }

        warnings.add(
                "Invalid actions JSON root type. Expected an object or array, got: "
                        + root.getNodeType().toString());
        return Collections.emptyList();
    }

    private static String buildUnsupportedActionWarning(JsonNode actionNode, String actionId) {
        if (actionNode == null || actionNode.isNull()) {
            return "Unsupported action: (null entry)";
        }
        if (!actionNode.isObject()) {
            return "Unsupported action entry (expected object): "
                    + StringUtils.abbreviate(actionNode.toString(), 200);
        }
        String id = StringUtils.defaultString(actionId);
        if (!id.isBlank()) {
            return "Unsupported action: " + id;
        }
        return "Unsupported action (missing/blank id). Keys: "
                + String.join(", ", iterableFieldNames(actionNode));
    }

    private static List<String> iterableFieldNames(JsonNode obj) {
        List<String> names = new ArrayList<>();
        obj.fieldNames().forEachRemaining(names::add);
        return names;
    }

    private static String parseActionId(JsonNode actionNode) {
        if (actionNode == null || actionNode.isNull()) {
            return null;
        }
        if (actionNode.isTextual()) {
            return cleanupActionId(actionNode.asText());
        }
        if (!actionNode.isObject()) {
            return null;
        }

        // Primary field.
        String id = textOrNull(actionNode, "action");
        if (StringUtils.isNotBlank(id)) {
            return cleanupActionId(id);
        }

        // Common alternatives when models invent schemas.
        id =
                firstNonBlank(
                        textOrNull(actionNode, "id"),
                        textOrNull(actionNode, "type"),
                        textOrNull(actionNode, "name"));
        if (StringUtils.isNotBlank(id)) {
            return cleanupActionId(id);
        }

        id = firstNonBlank(textOrNull(actionNode, "tool"), textOrNull(actionNode, "tool_name"));
        if (StringUtils.isNotBlank(id)) {
            return cleanupActionId(id);
        }

        id = textOrNull(actionNode, "action_type");
        if (StringUtils.isNotBlank(id)) {
            return cleanupActionId(id);
        }

        return null;
    }

    private static String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String v : values) {
            if (StringUtils.isNotBlank(v)) {
                return v;
            }
        }
        return null;
    }

    private static String cleanupActionId(String raw) {
        if (raw == null) {
            return null;
        }
        String s = raw.trim().toLowerCase(Locale.ROOT).replace('-', '_');
        if (s.isEmpty()) {
            return null;
        }

        // Drop trailing punctuation or extra explanation (e.g. "open_fuzzer," or "open_fuzzer
        // (http)").
        int end = 0;
        while (end < s.length()) {
            char c = s.charAt(end);
            if (Character.isLetterOrDigit(c) || c == '_') {
                end++;
            } else {
                break;
            }
        }
        if (end == 0) {
            return null;
        }
        return s.substring(0, end);
    }

    @SafeVarargs
    private static List<String> firstNonEmptyPayloadList(
            List<String> current, List<String>... candidates) {
        if (current != null && !current.isEmpty()) {
            return current;
        }
        if (candidates == null) {
            return current;
        }
        for (List<String> c : candidates) {
            if (c != null && !c.isEmpty()) {
                return c;
            }
        }
        return current;
    }

    private static List<String> extractPayloadList(JsonNode node) {
        if (node == null || node.isNull()) {
            return List.of();
        }

        if (node.isArray()) {
            List<String> out = new ArrayList<>();
            for (JsonNode n : node) {
                if (n == null || n.isNull()) {
                    continue;
                }
                String v = StringUtils.trimToEmpty(n.asText());
                if (!v.isEmpty()) {
                    out.add(v);
                }
            }
            return out;
        }

        if (node.isTextual()) {
            String text = StringUtils.trimToEmpty(node.asText());
            if (text.isEmpty()) {
                return List.of();
            }
            String[] lines = text.split("\\R+");
            List<String> out = new ArrayList<>(lines.length);
            for (String line : lines) {
                String v = StringUtils.trimToEmpty(line);
                if (!v.isEmpty()) {
                    out.add(v);
                }
            }
            return out;
        }

        if (node.isObject()) {
            // Common wrapper shapes: { "values": [...] } or { "items": [...] }.
            List<String> values = extractPayloadList(node.get("payloads"));
            if (!values.isEmpty()) {
                return values;
            }
            values = extractPayloadList(node.get("values"));
            if (!values.isEmpty()) {
                return values;
            }
            values = extractPayloadList(node.get("items"));
            if (!values.isEmpty()) {
                return values;
            }
        }

        return List.of();
    }

    private static String extractActionsJson(String assistantText) {
        if (assistantText == null) {
            return null;
        }

        // Prefer the last actions block (in case the assistant includes multiple examples).
        int begin = assistantText.lastIndexOf(ACTIONS_BEGIN);
        if (begin >= 0) {
            int end = assistantText.indexOf(ACTIONS_END, begin + ACTIONS_BEGIN.length());
            String extracted =
                    end > begin
                            ? assistantText.substring(begin + ACTIONS_BEGIN.length(), end)
                            : assistantText.substring(begin + ACTIONS_BEGIN.length());
            return normalizeJsonCandidate(extracted);
        }

        // Fallback: accept a raw JSON object (common when users paste only the JSON).
        String trimmed = assistantText.trim();
        String raw = normalizeJsonCandidate(trimmed);
        if (raw != null
                && ((raw.startsWith("{") && raw.endsWith("}"))
                        || (raw.startsWith("[") && raw.endsWith("]")))) {
            return raw;
        }

        // Last resort: try to locate a JSON object containing an "actions" field.
        String embedded = extractEmbeddedActionsObject(assistantText);
        return normalizeJsonCandidate(embedded);
    }

    private static String extractEmbeddedActionsObject(String assistantText) {
        int idx = assistantText.indexOf("\"actions\"");
        while (idx >= 0) {
            int open = assistantText.lastIndexOf('{', idx);
            while (open >= 0) {
                int close = findMatchingBrace(assistantText, open);
                if (close > open) {
                    return assistantText.substring(open, close + 1);
                }
                open = assistantText.lastIndexOf('{', open - 1);
            }
            idx = assistantText.indexOf("\"actions\"", idx + 1);
        }
        return null;
    }

    private static int findMatchingBrace(String text, int openIndex) {
        int depth = 0;
        boolean inString = false;
        boolean escaped = false;

        for (int i = openIndex; i < text.length(); i++) {
            char c = text.charAt(i);

            if (inString) {
                if (escaped) {
                    escaped = false;
                    continue;
                }
                if (c == '\\') {
                    escaped = true;
                    continue;
                }
                if (c == '"') {
                    inString = false;
                }
                continue;
            }

            if (c == '"') {
                inString = true;
                continue;
            }

            if (c == '{') {
                depth++;
            } else if (c == '}') {
                depth--;
                if (depth == 0) {
                    return i;
                }
            }
        }
        return -1;
    }

    private static String normalizeJsonCandidate(String candidate) {
        if (StringUtils.isBlank(candidate)) {
            return null;
        }

        String trimmed = candidate.trim();

        // Handle common LLM formatting: code fences inside the actions block.
        // Example:
        // BEGIN_ZAP_ACTIONS
        // ```json
        // { ... }
        // ```
        // END_ZAP_ACTIONS
        if (trimmed.startsWith("```")) {
            int firstNewline = trimmed.indexOf('\n');
            int lastFence = trimmed.lastIndexOf("```");
            if (firstNewline > 0 && lastFence > firstNewline) {
                trimmed = trimmed.substring(firstNewline + 1, lastFence).trim();
            }
        }

        // Some models include markdown list bullets inside JSON arrays, like:
        // "actions": [
        //   * { ... },
        //   * { ... }
        // ]
        // Strip those bullets (and numbered list prefixes) on a per-line basis.
        trimmed = stripMarkdownListPrefixes(trimmed);

        return trimmed;
    }

    private static String stripMarkdownListPrefixes(String text) {
        String[] lines = text.split("\\R", -1);
        StringBuilder sb = new StringBuilder(text.length());
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            String stripped = stripMarkdownPrefixFromLine(line);
            sb.append(stripped);
            if (i < lines.length - 1) {
                sb.append('\n');
            }
        }
        return sb.toString();
    }

    private static String stripMarkdownPrefixFromLine(String line) {
        if (line == null || line.isEmpty()) {
            return line;
        }

        int idx = 0;
        while (idx < line.length() && Character.isWhitespace(line.charAt(idx))) {
            idx++;
        }
        if (idx >= line.length()) {
            return line;
        }

        char first = line.charAt(idx);
        if (first == '*' || first == '-') {
            int j = idx + 1;
            while (j < line.length() && Character.isWhitespace(line.charAt(j))) {
                j++;
            }
            if (j < line.length()) {
                char next = line.charAt(j);
                if (next == '{' || next == '"' || next == '[') {
                    return line.substring(0, idx) + line.substring(j);
                }
            }
            return line;
        }

        if (Character.isDigit(first)) {
            int j = idx;
            while (j < line.length() && Character.isDigit(line.charAt(j))) {
                j++;
            }
            if (j < line.length() && line.charAt(j) == '.') {
                j++;
                while (j < line.length() && Character.isWhitespace(line.charAt(j))) {
                    j++;
                }
                if (j < line.length()) {
                    char next = line.charAt(j);
                    if (next == '{' || next == '"' || next == '[') {
                        return line.substring(0, idx) + line.substring(j);
                    }
                }
            }
        }

        return line;
    }

    private static String textOrNull(JsonNode node, String field) {
        JsonNode v = node.get(field);
        if (v == null || v.isNull()) {
            return null;
        }
        String text = v.asText();
        return StringUtils.isBlank(text) ? null : text;
    }

    private static HttpMessageLocation.Location parseLocation(String value) {
        if (StringUtils.isBlank(value)) {
            return null;
        }

        String v = StringUtils.trimToEmpty(value).toUpperCase().replace('-', '_');
        if ("REQUEST_HEADER".equals(v) || "HTTP_REQUEST_HEADER".equals(v)) {
            return HttpMessageLocation.Location.REQUEST_HEADER;
        }
        if ("REQUEST_BODY".equals(v) || "HTTP_REQUEST_BODY".equals(v)) {
            return HttpMessageLocation.Location.REQUEST_BODY;
        }
        return null;
    }

    private static boolean hasHistoryOrRequest(int historyId, LlmZapRequestData request) {
        return historyId > 0 || (request != null && StringUtils.isNotBlank(request.header()));
    }

    private static String validate(
            LlmZapActionType type,
            int historyId,
            String note,
            List<String> tags,
            HttpMessageLocation.Location location,
            int start,
            int end,
            String payload,
            List<String> payloads,
            LlmZapRequestData request) {
        if (type == null) {
            return "Missing action type.";
        }

        return switch (type) {
            case SET_HISTORY_NOTE -> {
                if (historyId <= 0) {
                    yield "Missing or invalid history_id for action: " + type.getId();
                }
                yield null;
            }
            case ADD_HISTORY_TAGS -> {
                if (historyId <= 0) {
                    yield "Missing or invalid history_id for action: " + type.getId();
                }
                yield null;
            }
            case OPEN_REQUESTER_DIALOG, OPEN_REQUESTER_TAB -> {
                if (StringUtils.isBlank(payload)) {
                    yield "Missing payload for action: " + type.getId();
                }
                yield null;
            }
            case OPEN_FUZZER -> {
                if (payloads == null || payloads.isEmpty()) {
                    yield "Missing payloads for action: " + type.getId();
                }
                yield null;
            }
        };
    }
}
