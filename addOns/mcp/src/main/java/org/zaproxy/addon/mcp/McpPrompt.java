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
 * Defines an MCP prompt that can be retrieved by clients.
 *
 * <p>Prompts are discovered via {@code prompts/list} and retrieved via {@code prompts/get}. They
 * provide reusable instruction templates that guide an AI model through multi-step ZAP workflows.
 */
public interface McpPrompt {

    /**
     * Returns the unique name of the prompt.
     *
     * @return the prompt name
     */
    String getName();

    /**
     * Returns a human-readable description of what the prompt does.
     *
     * @return the prompt description
     */
    String getDescription();

    /**
     * Returns the argument definitions for this prompt.
     *
     * @return the list of arguments (may be empty)
     */
    List<PromptArgument> getArguments();

    /**
     * Returns the prompt messages for the given arguments.
     *
     * @param arguments the argument values supplied by the client
     * @return the list of messages to return to the client
     */
    List<PromptMessage> getMessages(Map<String, String> arguments);

    /**
     * Defines a single argument accepted by a prompt.
     *
     * @param name the argument name
     * @param description human-readable description of the argument
     * @param required whether the argument must be supplied
     */
    record PromptArgument(String name, String description, boolean required) {}

    /**
     * A single message in a prompt response.
     *
     * @param role the message role ({@code "user"} or {@code "assistant"})
     * @param text the message text content
     */
    record PromptMessage(String role, String text) {}
}
