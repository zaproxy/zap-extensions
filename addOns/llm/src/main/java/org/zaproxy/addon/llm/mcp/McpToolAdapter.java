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
package org.zaproxy.addon.llm.mcp;

import dev.langchain4j.agent.tool.ToolExecutionRequest;
import dev.langchain4j.agent.tool.ToolSpecification;
import dev.langchain4j.model.chat.request.json.JsonArraySchema;
import dev.langchain4j.model.chat.request.json.JsonObjectSchema;
import dev.langchain4j.model.chat.request.json.JsonSchemaElement;
import dev.langchain4j.model.chat.request.json.JsonStringSchema;
import dev.langchain4j.service.tool.ToolExecutor;
import dev.langchain4j.service.tool.ToolProvider;
import dev.langchain4j.service.tool.ToolProviderRequest;
import dev.langchain4j.service.tool.ToolProviderResult;
import java.util.LinkedHashMap;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.addon.mcp.McpTool;
import org.zaproxy.addon.mcp.McpTool.InputSchema;
import org.zaproxy.addon.mcp.McpToolException;
import org.zaproxy.addon.mcp.McpToolRegistry;

public class McpToolAdapter implements ToolProvider {

    private static final Logger LOGGER = LogManager.getLogger(McpToolAdapter.class);

    private final McpToolRegistry registry;

    public McpToolAdapter(McpToolRegistry registry) {
        this.registry = registry;
    }

    @Override
    public ToolProviderResult provideTools(ToolProviderRequest request) {
        Map<ToolSpecification, ToolExecutor> tools = new LinkedHashMap<>();
        for (McpTool tool : registry.getTools()) {
            ToolSpecification spec =
                    ToolSpecification.builder()
                            .name(tool.getName())
                            .description(tool.getDescription())
                            .parameters(toJsonObjectSchema(tool.getInputSchema()))
                            .build();
            tools.put(spec, toExecutor(tool));
        }
        return ToolProviderResult.builder().addAll(tools).build();
    }

    private static JsonObjectSchema toJsonObjectSchema(InputSchema schema) {
        JsonObjectSchema.Builder builder = JsonObjectSchema.builder();
        for (Map.Entry<String, InputSchema.PropertyDef> entry : schema.properties().entrySet()) {
            builder.addProperty(entry.getKey(), toJsonSchema(entry.getValue()));
        }
        if (!schema.required().isEmpty()) {
            builder.required(schema.required());
        }
        return builder.build();
    }

    private static JsonSchemaElement toJsonSchema(InputSchema.PropertyDef def) {
        if ("array".equals(def.type())) {
            return JsonArraySchema.builder()
                    .description(def.description())
                    .items(JsonStringSchema.builder().build())
                    .build();
        }
        return JsonStringSchema.builder().description(def.description()).build();
    }

    // Error strings are intentionally not i18n — they are returned to the LLM as tool results,
    // not shown to the user directly, and the LLM must understand them to act on them.
    private static ToolExecutor toExecutor(McpTool tool) {
        return (ToolExecutionRequest toolRequest, Object memoryId) -> {
            McpTool.ToolArguments arguments;
            try {
                arguments = McpTool.ToolArguments.fromJson(toolRequest.arguments());
            } catch (Exception e) {
                LOGGER.debug("Failed to parse arguments for tool {}.", tool.getName(), e);
                return "Failed to parse arguments for tool "
                        + tool.getName()
                        + ": "
                        + e.getMessage();
            }
            try {
                return tool.execute(arguments).text();
            } catch (McpToolException e) {
                LOGGER.debug("Failed to execute tool {}.", tool.getName(), e);
                return "Failed to execute tool " + tool.getName() + ": " + e.getMessage();
            }
        };
    }
}
