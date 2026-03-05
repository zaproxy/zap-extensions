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
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Locale;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.mcp.resources.HistoryEntryResource;
import org.zaproxy.addon.mcp.tools.ZapVersionTool;
import org.zaproxy.zap.utils.I18N;

/** Unit tests for {@link McpRequestHandler}. */
class McpRequestHandlerUnitTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private McpToolRegistry toolRegistry;
    private McpResourceRegistry resourceRegistry;
    private McpRequestHandler requestHandler;

    @BeforeEach
    void setUp() {
        Constant.messages = new I18N(Locale.ROOT);
        toolRegistry = new McpToolRegistry();
        resourceRegistry = new McpResourceRegistry();
        toolRegistry.registerTool(new ZapVersionTool());
        requestHandler = new McpRequestHandler(toolRegistry, resourceRegistry, "");
    }

    @Test
    void shouldHandleInitialize() {
        String request =
                """
                {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}
                """;

        String response = requestHandler.handleRequest(request);

        assertThat(response, notNullValue());
        JsonNode json = parseJson(response);
        assertThat(json.get("result").get("protocolVersion").asText(), equalTo("2024-11-05"));
        assertThat(
                json.get("result").get("serverInfo").get("name").asText(),
                equalTo("ZAP MCP Server"));
    }

    @Test
    void shouldHandlePing() {
        String request = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}";

        String response = requestHandler.handleRequest(request);

        assertThat(response, notNullValue());
        JsonNode json = parseJson(response);
        assertThat(json.has("result"), equalTo(true));
    }

    @Test
    void shouldHandleToolsList() {
        String request = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}";

        String response = requestHandler.handleRequest(request);

        assertThat(response, notNullValue());
        JsonNode json = parseJson(response);
        JsonNode tools = json.get("result").get("tools");
        assertThat(tools.isArray(), equalTo(true));
        assertThat(tools.size(), equalTo(1));
        assertThat(tools.get(0).get("name").asText(), equalTo("zap_version"));
    }

    @Test
    void shouldHandleToolsCall() {
        String request =
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"zap_version\",\"arguments\":{}}}";

        String response = requestHandler.handleRequest(request);

        assertThat(response, notNullValue());
        JsonNode json = parseJson(response);
        assertThat(json.has("error"), equalTo(false));
        JsonNode content = json.get("result").get("content").get(0);
        assertThat(content.get("type").asText(), equalTo("text"));
        assertThat(content.has("text"), equalTo(true));
    }

    @Test
    void shouldReturnErrorForInvalidJson() {
        String response = requestHandler.handleRequest("not json");

        assertThat(response, containsString("\"error\""));
        JsonNode json = parseJson(response);
        assertThat(json.get("error").get("code").asInt(), equalTo(-32603));
        assertThat(json.get("error").get("message").asText(), containsString("Internal error"));
    }

    @Test
    void shouldReturnErrorForMissingMethod() {
        String request = "{\"jsonrpc\":\"2.0\",\"id\":1}";

        String response = requestHandler.handleRequest(request);

        assertThat(response, containsString("\"error\""));
        JsonNode json = parseJson(response);
        assertThat(
                json.get("error").get("message").asText(), containsString("method not specified"));
    }

    @Test
    void shouldReturnErrorForUnknownMethod() {
        String request = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"unknown/method\"}";

        String response = requestHandler.handleRequest(request);

        assertThat(response, containsString("\"error\""));
        JsonNode json = parseJson(response);
        assertThat(
                json.get("error").get("code").asInt(),
                equalTo(McpRequestHandler.ERROR_METHOD_NOT_FOUND));
        assertThat(json.get("error").get("message").asText(), containsString("Method not found"));
    }

    @Test
    void shouldReturnErrorForUnknownTool() {
        String request =
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"unknown_tool\",\"arguments\":{}}}";

        String response = requestHandler.handleRequest(request);

        assertThat(response, containsString("\"error\""));
        JsonNode json = parseJson(response);
        assertThat(json.get("error").get("message").asText(), containsString("Unknown tool"));
    }

    @Test
    void shouldHandleResourcesList() {
        resourceRegistry.registerResource(new HistoryEntryResource());

        String request = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/list\"}";

        String response = requestHandler.handleRequest(request);

        assertThat(response, notNullValue());
        JsonNode json = parseJson(response);
        JsonNode resources = json.get("result").get("resources");
        assertThat(resources.isArray(), equalTo(true));
    }

    private static JsonNode parseJson(String json) {
        try {
            return OBJECT_MAPPER.readTree(json);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse JSON: " + json, e);
        }
    }
}
