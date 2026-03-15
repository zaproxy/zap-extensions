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
package org.zaproxy.addon.mcp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Defines an MCP tool that can be invoked by clients.
 *
 * <p>Tools are discovered via {@code tools/list} and executed via {@code tools/call}.
 */
public interface McpTool {

    public static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    /**
     * Returns the unique name of the tool. Used as the identifier when invoking the tool.
     *
     * @return the tool name
     */
    String getName();

    /**
     * Returns a human-readable description of what the tool does.
     *
     * @return the tool description
     */
    String getDescription();

    /**
     * Returns the JSON Schema for the tool's input parameters.
     *
     * <p>Should include {@code type}, {@code properties}, and {@code required} as per JSON Schema
     * specification.
     *
     * @return the input schema as a JSON object
     */
    ObjectNode getInputSchema();

    /**
     * Executes the tool with the given arguments.
     *
     * @param arguments the arguments from the client (may be empty)
     * @return the result of the tool execution
     * @throws McpToolException if the tool execution fails
     */
    McpToolResult execute(JsonNode arguments) throws McpToolException;
}
