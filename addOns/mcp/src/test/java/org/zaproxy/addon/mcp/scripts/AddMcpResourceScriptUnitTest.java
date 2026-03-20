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
import static org.hamcrest.Matchers.emptyOrNullString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
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
import org.zaproxy.addon.mcp.McpResource;
import org.zaproxy.addon.mcp.McpResourceRegistry;
import org.zaproxy.zap.extension.graaljs.GraalJsEngineWrapper;
import org.zaproxy.zap.utils.I18N;

/** Unit tests for the {@code Add MCP resource.js} extender script. */
class AddMcpResourceScriptUnitTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private McpResourceRegistry resourceRegistry;
    private ScriptEngine engine;

    @BeforeEach
    void setUp() throws Exception {
        Constant.messages = new I18N(Locale.ROOT);

        resourceRegistry = new McpResourceRegistry();

        ExtensionMcp extMcp =
                mock(ExtensionMcp.class, withSettings().strictness(Strictness.LENIENT));
        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionLoader.getExtension(ExtensionMcp.class)).willReturn(extMcp);
        given(extMcp.getResourceRegistry()).willReturn(resourceRegistry);

        Model model = mock(Model.class, withSettings().strictness(Strictness.LENIENT));
        Control.initSingletonForTesting(model, extensionLoader);

        engine =
                new GraalJsEngineWrapper(
                                AddMcpResourceScriptUnitTest.class.getClassLoader(),
                                List.of(),
                                null)
                        .getEngine();
        engine.put("control", Control.getSingleton());

        Path scriptPath =
                Path.of(
                        getClass()
                                .getResource("/scripts/templates/extender/Add MCP resource.js")
                                .toURI());
        try (Reader reader = Files.newBufferedReader(scriptPath, StandardCharsets.UTF_8)) {
            ((Compilable) engine).compile(reader).eval();
        }
    }

    @Test
    void shouldRegisterResourceOnInstall() throws Exception {
        // When
        ((Invocable) engine).invokeFunction("install", new Object[] {null});

        // Then
        assertThat(resourceRegistry.getResource("zap://example-resource"), is(notNullValue()));
    }

    @Test
    void shouldHaveCorrectDefaults() throws Exception {
        // Given
        ((Invocable) engine).invokeFunction("install", new Object[] {null});

        // When
        McpResource resource = resourceRegistry.getResource("zap://example-resource");

        // Then
        assertThat(resource.getUri(), equalTo("zap://example-resource"));
        assertThat(resource.getName(), equalTo("example-resource"));
        assertThat(
                resource.getDescription(),
                equalTo(
                        "An example MCP resource that returns sample data. Use this as a template for custom resources."));
    }

    @Test
    void shouldReturnJsonContentWithExpectedFields() throws Exception {
        // Given
        ((Invocable) engine).invokeFunction("install", new Object[] {null});
        McpResource resource = resourceRegistry.getResource("zap://example-resource");

        // When
        String content = resource.readContent();
        JsonNode json = OBJECT_MAPPER.readTree(content);

        // Then
        assertThat(json.get("message").asText(), equalTo("This is an example MCP resource"));
        assertThat(json.get("uri").asText(), equalTo("zap://example-resource"));
        assertThat(json.get("name").asText(), equalTo("example-resource"));
        assertThat(json.get("description").asText(), is(not(emptyOrNullString())));
        assertThat(json.get("timestamp").asText(), is(not(emptyOrNullString())));
    }

    @Test
    void shouldUnregisterResourceOnUninstall() throws Exception {
        // Given
        ((Invocable) engine).invokeFunction("install", new Object[] {null});
        assertThat(resourceRegistry.getResource("zap://example-resource"), is(notNullValue()));

        // When
        ((Invocable) engine).invokeFunction("uninstall", new Object[] {null});

        // Then
        assertThat(resourceRegistry.getResource("zap://example-resource"), is(nullValue()));
    }
}
