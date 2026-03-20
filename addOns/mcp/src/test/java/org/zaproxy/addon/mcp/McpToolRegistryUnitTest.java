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
import org.zaproxy.addon.mcp.tools.ZapInfoTool;
import org.zaproxy.addon.mcp.tools.ZapVersionTool;

/** Unit tests for {@link McpToolRegistry}. */
class McpToolRegistryUnitTest {

    private McpToolRegistry registry;

    @BeforeEach
    void setUp() {
        registry = new McpToolRegistry();
    }

    @Test
    void shouldRejectNullTool() {
        IllegalArgumentException e =
                assertThrows(IllegalArgumentException.class, () -> registry.registerTool(null));

        assertThat(e.getMessage(), is(equalTo("Tool must not be null")));
    }

    @Test
    void shouldRejectToolWithNullName() {
        McpTool tool = toolWithName(null);

        IllegalArgumentException e =
                assertThrows(IllegalArgumentException.class, () -> registry.registerTool(tool));

        assertThat(e.getMessage(), is(equalTo("Tool name must not be null or blank")));
    }

    @Test
    void shouldRejectToolWithBlankName() {
        McpTool tool = toolWithName("   ");

        IllegalArgumentException e =
                assertThrows(IllegalArgumentException.class, () -> registry.registerTool(tool));

        assertThat(e.getMessage(), is(equalTo("Tool name must not be null or blank")));
    }

    @Test
    void shouldRegisterAndGetTool() {
        McpTool tool = new ZapVersionTool();
        registry.registerTool(tool);

        assertThat(registry.getTool("zap_version"), is(equalTo(tool)));
    }

    @Test
    void shouldReplaceExistingToolWithSameName() {
        McpTool tool1 = new ZapVersionTool();
        McpTool tool2 = new ZapVersionTool();
        registry.registerTool(tool1);
        registry.registerTool(tool2);

        assertThat(registry.getTool("zap_version"), is(equalTo(tool2)));
    }

    @Test
    void shouldReturnNullForUnregisteredTool() {
        assertThat(registry.getTool("unknown"), is(nullValue()));
    }

    @Test
    void shouldUnregisterTool() {
        McpTool tool = new ZapVersionTool();
        registry.registerTool(tool);
        registry.unregisterTool("zap_version");

        assertThat(registry.getTool("zap_version"), is(nullValue()));
    }

    @Test
    void shouldReturnAllRegisteredTools() {
        McpTool tool1 = new ZapVersionTool();
        McpTool tool2 = new ZapInfoTool();
        registry.registerTool(tool1);
        registry.registerTool(tool2);

        assertThat(registry.getTools(), hasSize(2));
        assertThat(registry.getTools(), containsInAnyOrder(tool1, tool2));
    }

    @Test
    void shouldReturnEmptyListWhenNoToolsRegistered() {
        assertThat(registry.getTools(), is(empty()));
    }

    private static McpTool toolWithName(String name) {
        return new McpTool() {
            @Override
            public String getName() {
                return name;
            }

            @Override
            public String getDescription() {
                return "Test tool";
            }

            @Override
            public InputSchema getInputSchema() {
                return new InputSchema(Map.of(), List.of());
            }

            @Override
            public McpToolResult execute(ToolArguments arguments) throws McpToolException {
                return McpToolResult.success("ok");
            }
        };
    }
}
