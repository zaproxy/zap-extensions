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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Registry for MCP tools. Allows tools to be registered and looked up by name.
 *
 * <p>Thread-safe for concurrent registration and lookup.
 */
public class McpToolRegistry {

    private final Map<String, McpTool> tools = new ConcurrentHashMap<>();

    /**
     * Registers a tool. If a tool with the same name already exists, it is replaced.
     *
     * @param tool the tool to register
     * @throws IllegalArgumentException if the tool or its name is null
     */
    public void registerTool(McpTool tool) {
        if (tool == null) {
            throw new IllegalArgumentException("Tool must not be null");
        }
        String name = tool.getName();
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("Tool name must not be null or blank");
        }
        tools.put(name, tool);
    }

    /**
     * Unregisters a tool by name.
     *
     * @param name the name of the tool to unregister
     */
    public void unregisterTool(String name) {
        tools.remove(name);
    }

    /**
     * Gets a tool by name.
     *
     * @param name the tool name
     * @return the tool, or {@code null} if not registered
     */
    public McpTool getTool(String name) {
        return tools.get(name);
    }

    /**
     * Returns all registered tools.
     *
     * @return an unmodifiable list of tools
     */
    public List<McpTool> getTools() {
        return Collections.unmodifiableList(new ArrayList<>(tools.values()));
    }
}
