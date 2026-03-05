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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.mcp.McpTool;
import org.zaproxy.addon.mcp.McpToolException;
import org.zaproxy.addon.mcp.McpToolResult;
import org.zaproxy.zap.model.Context;

/**
 * MCP tool that creates a ZAP context with the given name, URL and optional include/exclude
 * regexes.
 */
public class ZapCreateContextTool implements McpTool {

    @Override
    public String getName() {
        return "zap_create_context";
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("mcp.tool.createcontext.desc");
    }

    @Override
    public ObjectNode getInputSchema() {
        ObjectNode schema = OBJECT_MAPPER.createObjectNode();
        schema.put("type", "object");
        ObjectNode properties = schema.putObject("properties");
        properties
                .putObject("name")
                .put("type", "string")
                .put(
                        "description",
                        Constant.messages.getString("mcp.tool.createcontext.param.name"));
        properties
                .putObject("url")
                .put("type", "string")
                .put(
                        "description",
                        Constant.messages.getString("mcp.tool.createcontext.param.url"));
        ObjectNode includeRegexes = properties.putObject("include_regexes");
        includeRegexes.put("type", "array");
        includeRegexes.putObject("items").put("type", "string");
        includeRegexes.put(
                "description",
                Constant.messages.getString("mcp.tool.createcontext.param.includeregexes"));
        ObjectNode excludeRegexes = properties.putObject("exclude_regexes");
        excludeRegexes.put("type", "array");
        excludeRegexes.putObject("items").put("type", "string");
        excludeRegexes.put(
                "description",
                Constant.messages.getString("mcp.tool.createcontext.param.excluderegexes"));
        schema.putArray("required").add("name").add("url");
        return schema;
    }

    @Override
    public McpToolResult execute(JsonNode arguments) throws McpToolException {
        JsonNode nameNode = arguments != null ? arguments.get("name") : null;
        if (nameNode == null || nameNode.isNull() || !nameNode.isTextual()) {
            throw new McpToolException(
                    Constant.messages.getString("mcp.tool.createcontext.error.missingname"));
        }
        String name = nameNode.asText().trim();
        if (name.isEmpty()) {
            throw new McpToolException(
                    Constant.messages.getString("mcp.tool.createcontext.error.emptyname"));
        }

        JsonNode urlNode = arguments != null ? arguments.get("url") : null;
        if (urlNode == null || urlNode.isNull() || !urlNode.isTextual()) {
            throw new McpToolException(
                    Constant.messages.getString("mcp.tool.createcontext.error.missingurl"));
        }
        String url = urlNode.asText().trim();
        if (url.isEmpty()) {
            throw new McpToolException(
                    Constant.messages.getString("mcp.tool.createcontext.error.emptyurl"));
        }

        try {
            new URI(url);
        } catch (Exception e) {
            throw new McpToolException(
                    Constant.messages.getString("mcp.tool.createcontext.error.invalidurl", url), e);
        }

        List<String> includeRegexes = parseStringArray(arguments, "include_regexes");
        List<String> excludeRegexes = parseStringArray(arguments, "exclude_regexes");

        String nameFinal = name;
        String urlFinal = url;
        List<String> includeFinal = includeRegexes;
        List<String> excludeFinal = excludeRegexes;

        try {
            Session session = Model.getSingleton().getSession();
            Context existing = session.getContext(nameFinal);
            if (existing != null) {
                session.deleteContext(existing);
            }
            Context context = session.getNewContext(nameFinal);

            context.addIncludeInContextRegex(urlFinal + ".*");
            for (String regex : includeFinal) {
                if (regex != null && !regex.isBlank()) {
                    context.addIncludeInContextRegex(regex.trim());
                }
            }
            for (String regex : excludeFinal) {
                if (regex != null && !regex.isBlank()) {
                    context.addExcludeFromContextRegex(regex.trim());
                }
            }
            session.saveContext(context);
        } catch (Exception e) {
            Throwable cause = e.getCause();
            if (cause instanceof McpToolException mte) {
                throw mte;
            }
            throw new McpToolException(
                    Constant.messages.getString(
                            "mcp.tool.createcontext.error.failed", e.getMessage()),
                    e);
        }

        return McpToolResult.success(
                Constant.messages.getString("mcp.tool.createcontext.success", name));
    }

    private static List<String> parseStringArray(JsonNode arguments, String key) {
        List<String> result = new ArrayList<>();
        JsonNode node = arguments != null ? arguments.get(key) : null;
        if (node != null && node.isArray()) {
            for (JsonNode item : node) {
                if (item != null && item.isTextual()) {
                    result.add(item.asText());
                }
            }
        }
        return result;
    }
}
