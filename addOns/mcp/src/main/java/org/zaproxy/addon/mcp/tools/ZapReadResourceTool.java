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

import java.util.LinkedHashMap;
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
 * MCP tool that reads a registered resource by URI. Intended for clients that only support tools
 * (e.g. the LLM bridge); clients that support the resources capability can use {@code
 * resources/read} instead.
 */
public class ZapReadResourceTool implements McpTool {

    private static final Logger LOGGER = LogManager.getLogger(ZapReadResourceTool.class);

    private final McpResourceRegistry registry;

    public ZapReadResourceTool(McpResourceRegistry registry) {
        this.registry = registry;
    }

    @Override
    public String getName() {
        return "zap_read_resource";
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("mcp.tool.readresource.desc");
    }

    @Override
    public InputSchema getInputSchema() {
        Map<String, InputSchema.PropertyDef> properties = new LinkedHashMap<>();
        properties.put(
                "uri",
                InputSchema.PropertyDef.ofString(
                        Constant.messages.getString("mcp.tool.readresource.param.uri")));
        return new InputSchema(properties, List.of("uri"));
    }

    @Override
    public McpToolResult execute(ToolArguments arguments) throws McpToolException {
        String uri = arguments.getString("uri");
        if (uri == null || uri.isBlank()) {
            throw new McpToolException(
                    Constant.messages.getString("mcp.tool.readresource.error.missinguri"));
        }
        uri = uri.trim();

        McpResource resource = registry.getResource(uri);
        if (resource == null) {
            throw new McpToolException(
                    Constant.messages.getString("mcp.tool.readresource.error.unknownuri", uri));
        }

        try {
            return McpToolResult.success(resource.readContent(uri));
        } catch (Exception e) {
            LOGGER.error("Failed to read resource {}", uri, e);
            throw new McpToolException(
                    Constant.messages.getString(
                            "mcp.tool.readresource.error.failed",
                            e.getMessage() != null
                                    ? e.getMessage()
                                    : Constant.messages.getString("mcp.tool.error.unknown")));
        }
    }
}
