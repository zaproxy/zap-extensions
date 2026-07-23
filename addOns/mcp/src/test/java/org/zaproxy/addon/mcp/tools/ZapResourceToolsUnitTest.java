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
package org.zaproxy.addon.mcp.tools;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.mcp.ExtensionMcp;
import org.zaproxy.addon.mcp.McpResource;
import org.zaproxy.addon.mcp.McpResourceRegistry;
import org.zaproxy.addon.mcp.McpTool;
import org.zaproxy.addon.mcp.McpToolException;
import org.zaproxy.addon.mcp.McpToolResult;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit tests for {@link ZapListResourcesTool} and {@link ZapReadResourceTool}. */
class ZapResourceToolsUnitTest extends TestUtils {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private McpResourceRegistry registry;
    private ZapListResourcesTool listTool;
    private ZapReadResourceTool readTool;

    @BeforeEach
    void setUp() {
        mockMessages(new ExtensionMcp());
        registry = new McpResourceRegistry();
        listTool = new ZapListResourcesTool(registry);
        readTool = new ZapReadResourceTool(registry);
    }

    @Test
    void shouldHaveExpectedNamesAndSchemas() {
        assertThat(listTool.getName(), is(equalTo("zap_list_resources")));
        assertThat(listTool.getInputSchema().required().isEmpty(), is(true));

        assertThat(readTool.getName(), is(equalTo("zap_read_resource")));
        assertThat(readTool.getInputSchema().required(), is(equalTo(java.util.List.of("uri"))));
        assertThat(readTool.getInputSchema().properties().containsKey("uri"), is(true));
    }

    @Test
    void shouldListEmptyResources() throws Exception {
        McpToolResult result = listTool.execute(emptyArgs());

        assertThat(result.isError(), is(false));
        JsonNode json = MAPPER.readTree(result.text());
        assertThat(json.get("resources").isArray(), is(true));
        assertThat(json.get("resources").size(), is(equalTo(0)));
    }

    @Test
    void shouldListResourcesSortedByUri() throws Exception {
        registry.registerResource(resource("zap://b", "b-res", "B", "zap://b"));
        registry.registerResource(resource("zap://a/", "a-res", "A", "zap://a/{id}"));

        McpToolResult result = listTool.execute(emptyArgs());

        assertThat(result.isError(), is(false));
        JsonNode resources = MAPPER.readTree(result.text()).get("resources");
        assertThat(resources.size(), is(equalTo(2)));
        assertThat(resources.get(0).get("uri").asText(), is(equalTo("zap://a/{id}")));
        assertThat(resources.get(0).get("name").asText(), is(equalTo("a-res")));
        assertThat(resources.get(0).get("description").asText(), is(equalTo("A")));
        assertThat(resources.get(0).get("mimeType").asText(), is(equalTo("application/json")));
        assertThat(resources.get(1).get("uri").asText(), is(equalTo("zap://b")));
        assertThat(resources.get(1).get("name").asText(), is(equalTo("b-res")));
    }

    @Test
    void shouldReadResourceByExactUri() throws Exception {
        registry.registerResource(resource("zap://alerts", "alerts", "Alerts", "zap://alerts"));

        McpToolResult result = readTool.execute(args("uri", "zap://alerts"));

        assertThat(result.isError(), is(false));
        assertThat(result.text(), is(equalTo("{\"data\":\"zap://alerts\"}")));
    }

    @Test
    void shouldReadResourceByTemplateUri() throws Exception {
        registry.registerResource(
                resource("zap://history/", "history-entry", "History entry", "zap://history/{id}"));

        McpToolResult result = readTool.execute(args("uri", "zap://history/42"));

        assertThat(result.isError(), is(false));
        assertThat(result.text(), is(equalTo("{\"data\":\"zap://history/42\"}")));
    }

    @Test
    void shouldRejectMissingUri() {
        McpToolException e =
                assertThrows(McpToolException.class, () -> readTool.execute(emptyArgs()));

        assertThat(e.getMessage(), containsString("uri"));
    }

    @Test
    void shouldRejectBlankUri() {
        McpToolException e =
                assertThrows(McpToolException.class, () -> readTool.execute(args("uri", "   ")));

        assertThat(e.getMessage(), containsString("uri"));
    }

    @Test
    void shouldRejectUnknownUri() {
        McpToolException e =
                assertThrows(
                        McpToolException.class,
                        () -> readTool.execute(args("uri", "zap://unknown")));

        assertThat(e.getMessage(), containsString("zap://unknown"));
    }

    private static McpTool.ToolArguments emptyArgs() {
        return new McpTool.ToolArguments(Map.of(), Map.of());
    }

    private static McpTool.ToolArguments args(String key, String value) {
        return new McpTool.ToolArguments(Map.of(key, value), Map.of());
    }

    private static McpResource resource(
            String uri, String name, String description, String uriTemplate) {
        return new McpResource() {
            @Override
            public String getUri() {
                return uri;
            }

            @Override
            public String getName() {
                return name;
            }

            @Override
            public String getDescription() {
                return description;
            }

            @Override
            public String getUriTemplate() {
                return uriTemplate;
            }

            @Override
            public String readContent() {
                return "{\"data\":\"" + name + "\"}";
            }

            @Override
            public String readContent(String requestedUri) {
                return "{\"data\":\"" + requestedUri + "\"}";
            }
        };
    }
}
