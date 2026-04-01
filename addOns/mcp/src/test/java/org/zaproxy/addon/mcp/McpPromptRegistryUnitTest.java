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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EmptySource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

/** Unit tests for {@link McpPromptRegistry}. */
class McpPromptRegistryUnitTest {

    private McpPromptRegistry registry;

    @BeforeEach
    void setUp() {
        registry = new McpPromptRegistry();
    }

    @Test
    void shouldRejectNullPrompt() {
        IllegalArgumentException e =
                assertThrows(IllegalArgumentException.class, () -> registry.registerPrompt(null));

        assertThat(e.getMessage(), is(equalTo("Prompt must not be null")));
    }

    @ParameterizedTest
    @NullSource
    @EmptySource
    @ValueSource(strings = {" ", "\t"})
    void shouldRejectPromptWithEmptyName(String name) {
        McpPrompt prompt = promptWithName(name);

        IllegalArgumentException e =
                assertThrows(IllegalArgumentException.class, () -> registry.registerPrompt(prompt));

        assertThat(e.getMessage(), is(equalTo("Prompt name must not be null or blank")));
    }

    @Test
    void shouldRegisterAndGetPrompt() {
        McpPrompt prompt = promptWithName("test_prompt");
        registry.registerPrompt(prompt);

        assertThat(registry.getPrompt("test_prompt"), is(equalTo(prompt)));
    }

    @Test
    void shouldReplaceExistingPromptWithSameName() {
        McpPrompt prompt1 = promptWithName("test_prompt");
        McpPrompt prompt2 = promptWithName("test_prompt");
        registry.registerPrompt(prompt1);
        registry.registerPrompt(prompt2);

        assertThat(registry.getPrompt("test_prompt"), is(equalTo(prompt2)));
    }

    @Test
    void shouldReturnNullForUnregisteredPrompt() {
        assertThat(registry.getPrompt("unknown"), is(nullValue()));
    }

    @Test
    void shouldUnregisterPrompt() {
        McpPrompt prompt = promptWithName("test_prompt");
        registry.registerPrompt(prompt);
        registry.unregisterPrompt("test_prompt");

        assertThat(registry.getPrompt("test_prompt"), is(nullValue()));
    }

    @Test
    void shouldReturnAllRegisteredPrompts() {
        McpPrompt prompt1 = promptWithName("prompt_one");
        McpPrompt prompt2 = promptWithName("prompt_two");
        registry.registerPrompt(prompt1);
        registry.registerPrompt(prompt2);

        assertThat(registry.getPrompts(), hasSize(2));
        assertThat(registry.getPrompts(), containsInAnyOrder(prompt1, prompt2));
    }

    @Test
    void shouldReturnEmptyListWhenNoPromptsRegistered() {
        assertThat(registry.getPrompts(), is(empty()));
    }

    private static McpPrompt promptWithName(String name) {
        return new McpPrompt() {
            @Override
            public String getName() {
                return name;
            }

            @Override
            public String getDescription() {
                return "Test prompt";
            }

            @Override
            public List<PromptArgument> getArguments() {
                return List.of();
            }

            @Override
            public List<PromptMessage> getMessages(Map<String, String> arguments) {
                return List.of(new PromptMessage("user", "test message"));
            }
        };
    }
}
