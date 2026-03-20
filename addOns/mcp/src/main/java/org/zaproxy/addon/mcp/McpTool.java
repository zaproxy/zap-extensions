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

import java.util.List;
import java.util.Map;

/**
 * Defines an MCP tool that can be invoked by clients.
 *
 * <p>Tools are discovered via {@code tools/list} and executed via {@code tools/call}.
 */
public interface McpTool {

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
     * @return the input schema
     */
    InputSchema getInputSchema();

    /**
     * Executes the tool with the given arguments.
     *
     * @param arguments the arguments from the client (may be empty)
     * @return the result of the tool execution
     * @throws McpToolException if the tool execution fails
     */
    McpToolResult execute(ToolArguments arguments) throws McpToolException;

    /**
     * JSON Schema for a tool's input parameters.
     *
     * @param properties the named parameter definitions
     * @param required the names of required parameters
     */
    record InputSchema(Map<String, PropertyDef> properties, List<String> required) {

        /**
         * Definition of a single input parameter.
         *
         * @param type the JSON Schema type (e.g. {@code "string"}, {@code "array"})
         * @param description human-readable description of the parameter, or {@code null}
         * @param items for {@code "array"} type, the schema of each item; otherwise {@code null}
         */
        public record PropertyDef(String type, String description, PropertyDef items) {

            /** Creates a string parameter definition. */
            public static PropertyDef ofString(String description) {
                return new PropertyDef("string", description, null);
            }

            /** Creates a string-array parameter definition. */
            public static PropertyDef ofStringArray(String description) {
                return new PropertyDef("array", description, new PropertyDef("string", null, null));
            }
        }
    }

    /**
     * The arguments passed to a tool invocation. String parameters are accessed via {@link
     * #getString}, list parameters via {@link #getList}.
     *
     * @param strings the string-valued arguments
     * @param lists the list-valued arguments
     */
    record ToolArguments(Map<String, String> strings, Map<String, List<String>> lists) {

        /** Returns the string value for {@code key}, or {@code null} if absent. */
        public String getString(String key) {
            return strings.get(key);
        }

        /** Returns the list value for {@code key}, or an empty list if absent. */
        public List<String> getList(String key) {
            return lists.getOrDefault(key, List.of());
        }
    }
}
