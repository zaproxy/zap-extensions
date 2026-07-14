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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;

import dev.langchain4j.agent.tool.ToolExecutionRequest;
import dev.langchain4j.model.chat.request.json.JsonArraySchema;
import dev.langchain4j.model.chat.request.json.JsonObjectSchema;
import dev.langchain4j.model.chat.request.json.JsonStringSchema;
import dev.langchain4j.service.tool.AiServiceTool;
import dev.langchain4j.service.tool.ToolProviderRequest;
import dev.langchain4j.service.tool.ToolProviderResult;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.mcp.McpTool;
import org.zaproxy.addon.mcp.McpTool.InputSchema;
import org.zaproxy.addon.mcp.McpTool.InputSchema.PropertyDef;
import org.zaproxy.addon.mcp.McpTool.ToolArguments;
import org.zaproxy.addon.mcp.McpToolException;
import org.zaproxy.addon.mcp.McpToolRegistry;
import org.zaproxy.addon.mcp.McpToolResult;

class McpToolAdapterUnitTest {

    private McpToolRegistry registry;
    private McpToolAdapter adapter;
    private ToolProviderRequest request;

    @BeforeEach
    void setUp() {
        registry = new McpToolRegistry();
        adapter = new McpToolAdapter(registry);
        request = mock(ToolProviderRequest.class);
    }

    @Test
    void shouldReturnNoToolsForEmptyRegistry() {
        ToolProviderResult result = adapter.provideTools(request);

        assertThat(result.aiServiceTools(), is(empty()));
    }

    @Test
    void shouldExposeRegisteredToolNameAndDescription() {
        registry.registerTool(stubTool("my_tool", "Does something useful", emptySchema()));

        List<AiServiceTool> tools = adapter.provideTools(request).aiServiceTools();

        assertThat(tools, hasSize(1));
        assertThat(tools.get(0).toolSpecification().name(), equalTo("my_tool"));
        assertThat(
                tools.get(0).toolSpecification().description(), equalTo("Does something useful"));
    }

    @Test
    void shouldExposeAllRegisteredTools() {
        registry.registerTool(stubTool("tool_a", "Tool A", emptySchema()));
        registry.registerTool(stubTool("tool_b", "Tool B", emptySchema()));
        registry.registerTool(stubTool("tool_c", "Tool C", emptySchema()));

        List<AiServiceTool> tools = adapter.provideTools(request).aiServiceTools();

        assertThat(tools, hasSize(3));
    }

    @Test
    void shouldTranslateStringPropertyToJsonStringSchema() {
        InputSchema schema =
                new InputSchema(
                        Map.of("url", PropertyDef.ofString("The target URL")), List.of("url"));
        registry.registerTool(stubTool("t", "desc", schema));

        JsonObjectSchema params =
                adapter.provideTools(request)
                        .aiServiceTools()
                        .get(0)
                        .toolSpecification()
                        .parameters();

        assertThat(params.properties().get("url"), instanceOf(JsonStringSchema.class));
        assertThat(
                ((JsonStringSchema) params.properties().get("url")).description(),
                equalTo("The target URL"));
    }

    @Test
    void shouldTranslateArrayPropertyToJsonArraySchema() {
        InputSchema schema =
                new InputSchema(
                        Map.of("tags", PropertyDef.ofStringArray("A list of tags")), List.of());
        registry.registerTool(stubTool("t", "desc", schema));

        JsonObjectSchema params =
                adapter.provideTools(request)
                        .aiServiceTools()
                        .get(0)
                        .toolSpecification()
                        .parameters();

        assertThat(params.properties().get("tags"), instanceOf(JsonArraySchema.class));
        assertThat(
                ((JsonArraySchema) params.properties().get("tags")).description(),
                equalTo("A list of tags"));
    }

    @Test
    void shouldPopulateRequiredFields() {
        InputSchema schema =
                new InputSchema(
                        Map.of(
                                "target", PropertyDef.ofString("Target URL"),
                                "policy", PropertyDef.ofString("Scan policy")),
                        List.of("target"));
        registry.registerTool(stubTool("t", "desc", schema));

        JsonObjectSchema params =
                adapter.provideTools(request)
                        .aiServiceTools()
                        .get(0)
                        .toolSpecification()
                        .parameters();

        assertThat(params.required(), equalTo(List.of("target")));
    }

    @Test
    void shouldReturnToolResultText() throws Exception {
        registry.registerTool(stubTool("t", "d", emptySchema(), McpToolResult.success("ok")));
        AiServiceTool tool = adapter.provideTools(request).aiServiceTools().get(0);

        String result = executeWith(tool, "{}");

        assertThat(result, equalTo("ok"));
    }

    @Test
    void shouldReturnErrorTextOnMcpToolException() throws Exception {
        registry.registerTool(
                makeTool(
                        "fail_tool",
                        "Always fails",
                        emptySchema(),
                        args -> {
                            throw new McpToolException("something went wrong");
                        }));
        AiServiceTool tool = adapter.provideTools(request).aiServiceTools().get(0);

        String result = executeWith(tool, "{}");

        assertThat(result, containsString("fail_tool"));
        assertThat(result, containsString("something went wrong"));
    }

    @Test
    void shouldPassStringArgumentToTool() throws Exception {
        AtomicReference<ToolArguments> captured = new AtomicReference<>();
        registry.registerTool(capturingTool("t", captured));
        AiServiceTool tool = adapter.provideTools(request).aiServiceTools().get(0);

        executeWith(tool, "{\"target\":\"https://example.com\"}");

        assertThat(captured.get().getString("target"), equalTo("https://example.com"));
    }

    @Test
    void shouldPassListArgumentToTool() throws Exception {
        AtomicReference<ToolArguments> captured = new AtomicReference<>();
        registry.registerTool(capturingTool("t", captured));
        AiServiceTool tool = adapter.provideTools(request).aiServiceTools().get(0);

        executeWith(tool, "{\"tags\":[\"a\",\"b\",\"c\"]}");

        assertThat(captured.get().getList("tags"), equalTo(List.of("a", "b", "c")));
    }

    @Test
    void shouldHandleEmptyJsonArguments() throws Exception {
        AtomicReference<ToolArguments> captured = new AtomicReference<>();
        registry.registerTool(capturingTool("t", captured));
        AiServiceTool tool = adapter.provideTools(request).aiServiceTools().get(0);

        executeWith(tool, "{}");

        assertThat(captured.get().getString("anything"), equalTo(null));
        assertThat(captured.get().getList("anything"), is(empty()));
    }

    @Test
    void shouldReturnErrorTextOnMalformedArguments() throws Exception {
        AtomicReference<ToolArguments> captured = new AtomicReference<>();
        registry.registerTool(capturingTool("t", captured));
        AiServiceTool tool = adapter.provideTools(request).aiServiceTools().get(0);

        String result = executeWith(tool, "not valid json {{{");

        assertThat(result, containsString("Failed to parse arguments for tool t"));
        assertThat(captured.get(), equalTo(null));
    }

    @Test
    void shouldHandleNullArguments() throws Exception {
        AtomicReference<ToolArguments> captured = new AtomicReference<>();
        registry.registerTool(capturingTool("t", captured));
        AiServiceTool tool = adapter.provideTools(request).aiServiceTools().get(0);

        executeWith(tool, null);

        assertThat(captured.get().getString("anything"), equalTo(null));
    }

    // --- helpers ---

    @FunctionalInterface
    interface ToolExecuteFn {
        McpToolResult apply(ToolArguments args) throws McpToolException;
    }

    private static String executeWith(AiServiceTool tool, String arguments) {
        ToolExecutionRequest req =
                ToolExecutionRequest.builder().name(tool.name()).arguments(arguments).build();
        return tool.toolExecutor().execute(req, null);
    }

    private static InputSchema emptySchema() {
        return new InputSchema(Map.of(), List.of());
    }

    private static McpTool makeTool(
            String name, String description, InputSchema schema, ToolExecuteFn fn) {
        return new McpTool() {
            @Override
            public String getName() {
                return name;
            }

            @Override
            public String getDescription() {
                return description;
            }

            @Override
            public InputSchema getInputSchema() {
                return schema;
            }

            @Override
            public McpToolResult execute(ToolArguments args) throws McpToolException {
                return fn.apply(args);
            }
        };
    }

    private static McpTool stubTool(String name, String description, InputSchema schema) {
        return makeTool(name, description, schema, args -> McpToolResult.success("result"));
    }

    private static McpTool stubTool(
            String name, String description, InputSchema schema, McpToolResult result) {
        return makeTool(name, description, schema, args -> result);
    }

    private static McpTool capturingTool(String name, AtomicReference<ToolArguments> captured) {
        return makeTool(
                name,
                "capturing",
                emptySchema(),
                args -> {
                    captured.set(args);
                    return McpToolResult.success("captured");
                });
    }
}
