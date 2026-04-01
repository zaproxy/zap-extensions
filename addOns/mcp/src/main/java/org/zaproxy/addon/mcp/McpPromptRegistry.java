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
 * Registry for MCP prompts. Allows prompts to be registered and looked up by name.
 *
 * <p>Thread-safe for concurrent registration and lookup.
 */
public class McpPromptRegistry {

    private final Map<String, McpPrompt> prompts = new ConcurrentHashMap<>();

    /**
     * Registers a prompt. If a prompt with the same name already exists, it is replaced.
     *
     * @param prompt the prompt to register
     * @throws IllegalArgumentException if the prompt or its name is null
     */
    public void registerPrompt(McpPrompt prompt) {
        if (prompt == null) {
            throw new IllegalArgumentException("Prompt must not be null");
        }
        String name = prompt.getName();
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("Prompt name must not be null or blank");
        }
        prompts.put(name, prompt);
    }

    /**
     * Unregisters a prompt by name.
     *
     * @param name the name of the prompt to unregister
     */
    public void unregisterPrompt(String name) {
        prompts.remove(name);
    }

    /**
     * Gets a prompt by name.
     *
     * @param name the prompt name
     * @return the prompt, or {@code null} if not registered
     */
    public McpPrompt getPrompt(String name) {
        return prompts.get(name);
    }

    /**
     * Returns all registered prompts.
     *
     * @return an unmodifiable list of prompts
     */
    public List<McpPrompt> getPrompts() {
        return Collections.unmodifiableList(new ArrayList<>(prompts.values()));
    }
}
