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

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.mcp.McpResource;
import org.zaproxy.addon.mcp.McpResourceRegistry;
import org.zaproxy.addon.mcp.McpTool;
import org.zaproxy.addon.mcp.McpToolException;
import org.zaproxy.addon.mcp.McpToolResult;

/**
 * MCP tool that lists registered resources. Intended for clients that only support tools (e.g. the
 * LLM bridge); clients that support the resources capability can use {@code resources/list}
 * instead.
 */
public class ZapListResourcesTool implements McpTool {

    private static final Logger LOGGER = LogManager.getLogger(ZapListResourcesTool.class);

    private final McpResourceRegistry registry;

    public ZapListResourcesTool(McpResourceRegistry registry) {
        this.registry = registry;
    }

    @Override
    public String getName() {
        return "zap_list_resources";
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("mcp.tool.listresources.desc");
    }

    @Override
    public InputSchema getInputSchema() {
        return new InputSchema(Map.of(), List.of());
    }

    @Override
    public McpToolResult execute(ToolArguments arguments) throws McpToolException {
        try {
            ArrayNode resourcesArray = McpResource.OBJECT_MAPPER.createArrayNode();
            registry.getResources().stream()
                    .sorted(Comparator.comparing(McpResource::getUri))
                    .forEach(
                            resource -> {
                                ObjectNode entry = resourcesArray.addObject();
                                entry.put("uri", resource.getUriTemplate());
                                entry.put("name", resource.getName());
                                entry.put("description", resource.getDescription());
                                entry.put("mimeType", resource.getMimeType());
                            });
            ObjectNode result = McpResource.OBJECT_MAPPER.createObjectNode();
            result.set("resources", resourcesArray);
            return McpToolResult.success(result.toString());
        } catch (Exception e) {
            LOGGER.error("Failed to list resources", e);
            throw new McpToolException(
                    Constant.messages.getString(
                            "mcp.tool.listresources.error.failed",
                            Constant.messages.getString("mcp.tool.error.unknown")));
        }
    }
}
