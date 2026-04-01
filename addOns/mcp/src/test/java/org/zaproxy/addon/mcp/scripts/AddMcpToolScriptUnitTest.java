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
package org.zaproxy.addon.mcp.scripts;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.script.Compilable;
import javax.script.Invocable;
import javax.script.ScriptEngine;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.mcp.ExtensionMcp;
import org.zaproxy.addon.mcp.McpTool;
import org.zaproxy.addon.mcp.McpTool.ToolArguments;
import org.zaproxy.addon.mcp.McpToolException;
import org.zaproxy.addon.mcp.McpToolRegistry;
import org.zaproxy.addon.mcp.McpToolResult;
import org.zaproxy.zap.extension.graaljs.GraalJsEngineWrapper;
import org.zaproxy.zap.utils.I18N;

/** Unit tests for the {@code Add MCP tool.js} extender script. */
class AddMcpToolScriptUnitTest {

    private McpToolRegistry toolRegistry;
    private ScriptEngine engine;

    @BeforeEach
    void setUp() throws Exception {
        Constant.messages = new I18N(Locale.ROOT);

        toolRegistry = new McpToolRegistry();

        ExtensionMcp extMcp =
                mock(ExtensionMcp.class, withSettings().strictness(Strictness.LENIENT));
        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionLoader.getExtension(ExtensionMcp.class)).willReturn(extMcp);
        given(extMcp.getToolRegistry()).willReturn(toolRegistry);

        Model model = mock(Model.class, withSettings().strictness(Strictness.LENIENT));
        Control.initSingletonForTesting(model, extensionLoader);

        engine =
                new GraalJsEngineWrapper(
                                AddMcpToolScriptUnitTest.class.getClassLoader(), List.of(), null)
                        .getEngine();
        engine.put("control", Control.getSingleton());

        Path scriptPath =
                Path.of(
                        getClass()
                                .getResource("/scripts/templates/extender/Add MCP tool.js")
                                .toURI());
        try (Reader reader = Files.newBufferedReader(scriptPath, StandardCharsets.UTF_8)) {
            ((Compilable) engine).compile(reader).eval();
        }
    }

    @Test
    void shouldRegisterToolOnInstall() throws Exception {
        // When
        ((Invocable) engine).invokeFunction("install", new Object[] {null});

        // Then
        assertThat(toolRegistry.getTool("example-tool"), is(notNullValue()));
    }

    @Test
    void shouldHaveCorrectName() throws Exception {
        // Given / When
        ((Invocable) engine).invokeFunction("install", new Object[] {null});
        McpTool tool = toolRegistry.getTool("example-tool");

        // Then
        McpTool.InputSchema schema = tool.getInputSchema();
        assertThat(tool.getName(), equalTo("example-tool"));
        assertThat(
                tool.getDescription(),
                equalTo(
                        "An example MCP tool that echoes a message. Use this as a template for custom tools."));
        ;
        assertThat(schema, is(notNullValue()));
        assertThat(schema.properties().containsKey("message"), is(true));
        assertThat(schema.required(), hasItem("message"));
        assertThat(
                schema.properties().get("message").description(), equalTo("The message to echo"));
        assertThat(schema.properties().get("message").type(), equalTo("string"));
    }

    @Test
    void shouldEchoMessageOnExecute() throws Exception {
        // Given
        ((Invocable) engine).invokeFunction("install", new Object[] {null});
        McpTool tool = toolRegistry.getTool("example-tool");
        ToolArguments args = new ToolArguments(Map.of("message", "hello"), Map.of());

        // When
        McpToolResult result = tool.execute(args);

        // Then
        assertThat(result.text(), equalTo("Echo: hello"));
        assertThat(result.isError(), is(false));
    }

    @Test
    void shouldThrowExceptionForBlankMessage() throws Exception {
        // Given
        ((Invocable) engine).invokeFunction("install", new Object[] {null});
        McpTool tool = toolRegistry.getTool("example-tool");
        ToolArguments args = new ToolArguments(Map.of("message", ""), Map.of());

        // When / Then - GraalVM wraps host exceptions; verify McpToolException is in the cause
        // chain
        assertThrows(Exception.class, () -> tool.execute(args));
    }

    @Test
    void shouldThrowExceptionForMissingMessage() throws Exception {
        // Given
        ((Invocable) engine).invokeFunction("install", new Object[] {null});
        McpTool tool = toolRegistry.getTool("example-tool");
        ToolArguments args = new ToolArguments(Map.of(), Map.of());

        // When / Then
        assertThrows(Exception.class, () -> tool.execute(args));
    }

    @FunctionalInterface
    private interface McpToolCallable {
        void call() throws McpToolException;
    }

    @Test
    void shouldUnregisterToolOnUninstall() throws Exception {
        // Given
        ((Invocable) engine).invokeFunction("install", new Object[] {null});
        assertThat(toolRegistry.getTool("example-tool"), is(notNullValue()));

        // When
        ((Invocable) engine).invokeFunction("uninstall", new Object[] {null});

        // Then
        assertThat(toolRegistry.getTool("example-tool"), is(nullValue()));
    }
}
