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
package org.zaproxy.addon.mcp.tools;

import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.mcp.McpResource;
import org.zaproxy.addon.mcp.McpTool;
import org.zaproxy.addon.mcp.McpToolException;
import org.zaproxy.addon.mcp.McpToolResult;

/**
 * MCP tool that returns selected parts of a history entry, with optional windowing for request and
 * response bodies.
 */
public class ZapGetHistoryTool implements McpTool {

    static final String FIELD_REQUEST_HEADER = "requestHeader";
    static final String FIELD_REQUEST_BODY = "requestBody";
    static final String FIELD_RESPONSE_HEADER = "responseHeader";
    static final String FIELD_RESPONSE_BODY = "responseBody";

    static final List<String> DEFAULT_FIELDS = List.of(FIELD_REQUEST_HEADER, FIELD_RESPONSE_HEADER);
    static final Set<String> ALLOWED_FIELDS =
            new LinkedHashSet<>(
                    List.of(
                            FIELD_REQUEST_HEADER,
                            FIELD_REQUEST_BODY,
                            FIELD_RESPONSE_HEADER,
                            FIELD_RESPONSE_BODY));

    /** Default maximum characters returned for each included body. */
    static final int DEFAULT_MAX_BODY_CHARS = 4000;

    private static final Logger LOGGER = LogManager.getLogger(ZapGetHistoryTool.class);

    @Override
    public String getName() {
        return "zap_get_history";
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("mcp.tool.gethistory.desc");
    }

    @Override
    public InputSchema getInputSchema() {
        Map<String, InputSchema.PropertyDef> properties = new LinkedHashMap<>();
        properties.put(
                "id",
                InputSchema.PropertyDef.ofString(
                        Constant.messages.getString("mcp.tool.gethistory.param.id")));
        properties.put(
                "fields",
                InputSchema.PropertyDef.ofStringArray(
                        Constant.messages.getString("mcp.tool.gethistory.param.fields")));
        properties.put(
                "body_offset",
                InputSchema.PropertyDef.ofString(
                        Constant.messages.getString("mcp.tool.gethistory.param.bodyoffset")));
        properties.put(
                "max_body_chars",
                InputSchema.PropertyDef.ofString(
                        Constant.messages.getString("mcp.tool.gethistory.param.maxbodychars")));
        return new InputSchema(properties, List.of("id"));
    }

    @Override
    public McpToolResult execute(ToolArguments arguments) throws McpToolException {
        int id = parseId(arguments.getString("id"));
        Set<String> fields = parseFields(arguments.getList("fields"));
        int bodyOffset = parseOptionalInt(arguments.getString("body_offset"), 0, "body_offset");
        Integer maxBodyCharsArg =
                parseOptionalIntOrNull(arguments.getString("max_body_chars"), "max_body_chars");
        if (maxBodyCharsArg != null && maxBodyCharsArg <= 0) {
            throw new McpToolException(
                    Constant.messages.getString("mcp.tool.gethistory.error.invalidmaxbodychars"));
        }
        int maxBodyChars = maxBodyCharsArg != null ? maxBodyCharsArg : DEFAULT_MAX_BODY_CHARS;

        ExtensionHistory extHist =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionHistory.class);
        HistoryReference href = extHist.getHistoryReference(id);
        if (href == null) {
            throw new McpToolException(
                    Constant.messages.getString("mcp.tool.gethistory.error.notfound", id));
        }

        HttpMessage msg;
        try {
            msg = href.getHttpMessage();
        } catch (HttpMalformedHeaderException | DatabaseException e) {
            LOGGER.debug("Could not read history id {}: {}", id, e.getMessage());
            throw new McpToolException(
                    Constant.messages.getString("mcp.tool.gethistory.error.readfailed", id));
        }

        ObjectNode result = McpResource.OBJECT_MAPPER.createObjectNode();
        result.put("id", id);

        if (fields.contains(FIELD_REQUEST_HEADER)) {
            result.put(FIELD_REQUEST_HEADER, msg.getRequestHeader().toString());
        }
        if (fields.contains(FIELD_RESPONSE_HEADER)) {
            result.put(FIELD_RESPONSE_HEADER, msg.getResponseHeader().toString());
        }
        if (fields.contains(FIELD_REQUEST_BODY)) {
            putBodyWindow(
                    result,
                    FIELD_REQUEST_BODY,
                    msg.getRequestBody().toString(),
                    bodyOffset,
                    maxBodyChars);
        }
        if (fields.contains(FIELD_RESPONSE_BODY)) {
            putBodyWindow(
                    result,
                    FIELD_RESPONSE_BODY,
                    msg.getResponseBody().toString(),
                    bodyOffset,
                    maxBodyChars);
        }

        return McpToolResult.success(result.toString());
    }

    private static void putBodyWindow(
            ObjectNode result, String fieldName, String body, int bodyOffset, int maxBodyChars) {
        BodyWindow window = BodyWindow.of(body, bodyOffset, maxBodyChars);
        result.put(fieldName, window.text());
        result.put(fieldName + "Length", window.length());
        result.put(fieldName + "Offset", window.offset());
        result.put(fieldName + "Returned", window.returned());
        result.put(fieldName + "Truncated", window.truncated());
    }

    private static int parseId(String idValue) throws McpToolException {
        if (idValue == null || idValue.isBlank()) {
            throw new McpToolException(
                    Constant.messages.getString("mcp.tool.gethistory.error.missingid"));
        }
        try {
            return Integer.parseInt(idValue.trim());
        } catch (NumberFormatException e) {
            throw new McpToolException(
                    Constant.messages.getString("mcp.tool.gethistory.error.invalidid"));
        }
    }

    private static Set<String> parseFields(List<String> fieldsArg) throws McpToolException {
        if (fieldsArg == null || fieldsArg.isEmpty()) {
            return new LinkedHashSet<>(DEFAULT_FIELDS);
        }
        Set<String> fields = new LinkedHashSet<>();
        for (String field : fieldsArg) {
            if (field == null || field.isBlank()) {
                continue;
            }
            String normalized = field.trim();
            if (!ALLOWED_FIELDS.contains(normalized)) {
                throw new McpToolException(
                        Constant.messages.getString(
                                "mcp.tool.gethistory.error.unknownfield",
                                normalized,
                                String.join(", ", ALLOWED_FIELDS)));
            }
            fields.add(normalized);
        }
        if (fields.isEmpty()) {
            return new LinkedHashSet<>(DEFAULT_FIELDS);
        }
        return fields;
    }

    private static int parseOptionalInt(String value, int defaultValue, String paramName)
            throws McpToolException {
        Integer parsed = parseOptionalIntOrNull(value, paramName);
        return parsed != null ? parsed : defaultValue;
    }

    private static Integer parseOptionalIntOrNull(String value, String paramName)
            throws McpToolException {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            throw new McpToolException(
                    Constant.messages.getString(
                            "mcp.tool.gethistory.error.invalidint", paramName, value.trim()));
        }
    }

    /**
     * A window into a body string.
     *
     * @param text the returned body slice
     * @param offset the effective start index after clamping
     * @param length the full body length
     * @param returned the number of characters returned
     * @param truncated {@code true} if the full body was not returned
     */
    record BodyWindow(String text, int offset, int length, int returned, boolean truncated) {

        static BodyWindow of(String body, int bodyOffset, int maxChars) {
            String safeBody = body != null ? body : "";
            int length = safeBody.length();
            int start;
            if (bodyOffset >= 0) {
                start = Math.min(bodyOffset, length);
            } else {
                start = Math.max(0, length + bodyOffset);
            }
            int end = Math.min(start + Math.max(maxChars, 0), length);
            String text = safeBody.substring(start, end);
            int returned = end - start;
            boolean truncated = returned < length;
            return new BodyWindow(text, start, length, returned, truncated);
        }
    }
}
