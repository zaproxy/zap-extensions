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
package org.zaproxy.addon.mcp.importer;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.willAnswer;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.mcp.importer.McpImporter.ImportConfig;
import org.zaproxy.addon.mcp.importer.McpImporter.ImportResults;

/** Unit tests for {@link McpImporter}. */
class McpImporterUnitTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String SERVER_URL = "http://localhost:8282/mcp";

    /** Per-method response bodies dispatched by the mock sender. */
    private Map<String, String> responses;

    /** All messages passed to {@code sendAndReceive} during a test, in call order. */
    private List<HttpMessage> capturedRequests;

    private HttpSender sender;
    private McpImporter importer;

    @BeforeEach
    void setUp() throws IOException {
        capturedRequests = new ArrayList<>();
        responses = new HashMap<>();
        responses.put(
                "initialize",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{}}}");
        responses.put("notifications/initialized", "");
        responses.put("tools/list", "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[]}}");
        responses.put(
                "resources/list", "{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"resources\":[]}}");
        responses.put("prompts/list", "{\"jsonrpc\":\"2.0\",\"id\":4,\"result\":{\"prompts\":[]}}");

        sender = mock(HttpSender.class, withSettings().strictness(Strictness.LENIENT));
        importer = new McpImporter(sender);
        configureDefaultSender();
    }

    /** Stubs {@code sendAndReceive} to capture messages and return per-method responses. */
    private void configureDefaultSender() throws IOException {
        willAnswer(
                        inv -> {
                            HttpMessage msg = inv.getArgument(0);
                            capturedRequests.add(msg);
                            String body = msg.getRequestBody().toString();
                            JsonNode json = MAPPER.readTree(body);
                            String method = json.path("method").asText();
                            String responseBody =
                                    responses.getOrDefault(
                                            method, "{\"jsonrpc\":\"2.0\",\"result\":{}}");
                            msg.setResponseHeader(
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n");
                            msg.setResponseBody(responseBody);
                            return null;
                        })
                .given(sender)
                .sendAndReceive(any(HttpMessage.class));
    }

    // ---- invalid URL ----

    @Test
    void shouldReturnErrorForInvalidUrl() throws IOException {
        ImportResults results = importer.importServer(new ImportConfig("not a valid url %%", null));

        assertThat(results.requestCount(), is(0));
        assertThat(results.errors(), hasSize(1));
        assertThat(results.errors().get(0), containsString("Invalid server URL"));
        verify(sender, never()).sendAndReceive(any(HttpMessage.class));
    }

    // ---- initialize failure — aborts immediately ----

    @Test
    void shouldStopOnInitializeIoFailure() throws IOException {
        willThrow(new IOException("connection refused"))
                .given(sender)
                .sendAndReceive(any(HttpMessage.class));

        ImportResults results = importer.importServer(new ImportConfig(SERVER_URL, null));

        assertThat(results.requestCount(), is(0));
        assertThat(results.errors(), not(empty()));
        assertThat(results.errors().get(0), containsString("initialize"));
    }

    @Test
    void shouldStopOnInitializeHttpError() throws IOException {
        willAnswer(
                        inv -> {
                            HttpMessage msg = inv.getArgument(0);
                            msg.setResponseHeader("HTTP/1.1 401 Unauthorized\r\n\r\n");
                            msg.setResponseBody("");
                            return null;
                        })
                .given(sender)
                .sendAndReceive(any(HttpMessage.class));

        ImportResults results = importer.importServer(new ImportConfig(SERVER_URL, null));

        assertThat(results.requestCount(), is(1));
        assertThat(results.errors(), not(empty()));
        assertThat(results.errors().get(0), containsString("401"));
        // nothing beyond initialize should be sent
        assertThat(findRequestByMethod("tools/list"), is(nullValue()));
    }

    @Test
    void shouldStopOnInitializeJsonRpcError() throws IOException {
        responses.put(
                "initialize",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32600,\"message\":\"Unauthorized\"}}");

        ImportResults results = importer.importServer(new ImportConfig(SERVER_URL, null));

        assertThat(results.requestCount(), is(1));
        assertThat(results.errors(), not(empty()));
        assertThat(results.errors().get(0), containsString("MCP initialize failed"));
        assertThat(results.errors().get(0), containsString("Unauthorized"));
        assertThat(findRequestByMethod("tools/list"), is(nullValue()));
    }

    // ---- happy path ----

    @Test
    void shouldCountFiveRequestsForMinimalSuccessfulImport() throws IOException {
        // initialize + notifications/initialized + tools/list + resources/list + prompts/list
        ImportResults results = importer.importServer(new ImportConfig(SERVER_URL, null));

        assertThat(results.errors(), is(empty()));
        assertThat(results.requestCount(), is(5));
    }

    @Test
    void shouldIncludeAllFiveMethodsInMinimalImport() throws IOException {
        importer.importServer(new ImportConfig(SERVER_URL, null));

        assertThat(findRequestByMethod("initialize"), is(notNullValue()));
        assertThat(findRequestByMethod("notifications/initialized"), is(notNullValue()));
        assertThat(findRequestByMethod("tools/list"), is(notNullValue()));
        assertThat(findRequestByMethod("resources/list"), is(notNullValue()));
        assertThat(findRequestByMethod("prompts/list"), is(notNullValue()));
    }

    // ---- request structure ----

    @Test
    void shouldSendInitializeWithCorrectJsonRpcEnvelope() throws IOException {
        importer.importServer(new ImportConfig(SERVER_URL, null));

        HttpMessage msg = findRequestByMethod("initialize");
        JsonNode body = parseBody(msg);
        assertThat(body.path("jsonrpc").asText(), equalTo("2.0"));
        assertThat(body.has("id"), is(true));
        assertThat(body.path("method").asText(), equalTo("initialize"));
    }

    @Test
    void shouldSendInitializeWithProtocolVersionAndClientInfo() throws IOException {
        importer.importServer(new ImportConfig(SERVER_URL, null));

        JsonNode params = parseBody(findRequestByMethod("initialize")).path("params");
        assertThat(params.path("protocolVersion").asText(), equalTo("2024-11-05"));
        assertThat(params.path("clientInfo").path("name").asText(), equalTo("ZAP MCP Importer"));
    }

    @Test
    void shouldSendNotificationWithoutIdField() throws IOException {
        importer.importServer(new ImportConfig(SERVER_URL, null));

        JsonNode body = parseBody(findRequestByMethod("notifications/initialized"));
        assertThat(body.has("id"), is(false));
        assertThat(body.path("jsonrpc").asText(), equalTo("2.0"));
    }

    // ---- security key ----

    @Test
    void shouldSetAuthorizationHeaderOnAllRequestsWhenSecurityKeyProvided() throws IOException {
        importer.importServer(new ImportConfig(SERVER_URL, "Bearer secret-key"));

        assertThat(capturedRequests, not(empty()));
        for (HttpMessage msg : capturedRequests) {
            assertThat(
                    msg.getRequestHeader().getHeader("Authorization"),
                    equalTo("Bearer secret-key"));
        }
    }

    @Test
    void shouldNotSetAuthorizationHeaderWhenSecurityKeyIsNull() throws IOException {
        importer.importServer(new ImportConfig(SERVER_URL, null));

        for (HttpMessage msg : capturedRequests) {
            assertThat(msg.getRequestHeader().getHeader("Authorization"), is(nullValue()));
        }
    }

    @Test
    void shouldNotSetAuthorizationHeaderWhenSecurityKeyIsBlank() throws IOException {
        importer.importServer(new ImportConfig(SERVER_URL, "   "));

        for (HttpMessage msg : capturedRequests) {
            assertThat(msg.getRequestHeader().getHeader("Authorization"), is(nullValue()));
        }
    }

    // ---- tools ----

    @Test
    void shouldSendToolsCallForEachDiscoveredTool() throws IOException {
        responses.put(
                "tools/list", toolsListResponse("scan_target", schemaWithStringProp("target")));
        responses.put("tools/call", "{\"jsonrpc\":\"2.0\",\"id\":6,\"result\":{\"content\":[]}}");

        ImportResults results = importer.importServer(new ImportConfig(SERVER_URL, null));

        assertThat(results.requestCount(), is(6)); // 5 base + 1 tools/call
        HttpMessage toolsCallMsg = findRequestByMethod("tools/call");
        assertThat(toolsCallMsg, is(notNullValue()));
        assertThat(
                parseBody(toolsCallMsg).path("params").path("name").asText(),
                equalTo("scan_target"));
    }

    @Test
    void shouldSendOneToolsCallPerTool() throws IOException {
        responses.put(
                "tools/list",
                "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":["
                        + "{\"name\":\"tool_a\",\"inputSchema\":{}},"
                        + "{\"name\":\"tool_b\",\"inputSchema\":{}}"
                        + "]}}");

        ImportResults results = importer.importServer(new ImportConfig(SERVER_URL, null));

        assertThat(results.requestCount(), is(7)); // 5 base + 2 tools/call
        assertThat(findAllRequestsByMethod("tools/call"), hasSize(2));
    }

    @Test
    void shouldUseStringTemplatePlaceholderForStringSchemaProperties() throws IOException {
        responses.put(
                "tools/list",
                toolsListResponse(
                        "spider",
                        "{\"type\":\"object\",\"properties\":{"
                                + "\"target\":{\"type\":\"string\"},"
                                + "\"scope\":{\"type\":\"string\"}"
                                + "}}"));

        importer.importServer(new ImportConfig(SERVER_URL, null));

        JsonNode args =
                parseBody(findRequestByMethod("tools/call")).path("params").path("arguments");
        assertThat(args.path("target").asText(), equalTo("{target}"));
        assertThat(args.path("scope").asText(), equalTo("{scope}"));
    }

    @Test
    void shouldUseTypedDefaultsForNonStringSchemaProperties() throws IOException {
        responses.put(
                "tools/list",
                toolsListResponse(
                        "typed_tool",
                        "{\"type\":\"object\",\"properties\":{"
                                + "\"count\":{\"type\":\"integer\"},"
                                + "\"ratio\":{\"type\":\"number\"},"
                                + "\"flag\":{\"type\":\"boolean\"},"
                                + "\"items\":{\"type\":\"array\"},"
                                + "\"meta\":{\"type\":\"object\"}"
                                + "}}"));

        importer.importServer(new ImportConfig(SERVER_URL, null));

        JsonNode args =
                parseBody(findRequestByMethod("tools/call")).path("params").path("arguments");
        assertThat(args.path("count").intValue(), is(0));
        assertThat(args.path("ratio").intValue(), is(0));
        assertThat(args.path("flag").booleanValue(), is(false));
        assertThat(args.path("items").isArray(), is(true));
        assertThat(args.path("meta").isObject(), is(true));
    }

    // ---- resources ----

    @Test
    void shouldSendResourcesReadForEachDiscoveredResource() throws IOException {
        responses.put(
                "resources/list",
                "{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"resources\":[{\"uri\":\"zap://alerts\"}]}}");

        ImportResults results = importer.importServer(new ImportConfig(SERVER_URL, null));

        assertThat(results.requestCount(), is(6)); // 5 base + 1 resources/read
        HttpMessage readMsg = findRequestByMethod("resources/read");
        assertThat(readMsg, is(notNullValue()));
        assertThat(parseBody(readMsg).path("params").path("uri").asText(), equalTo("zap://alerts"));
    }

    @Test
    void shouldSendOneResourcesReadPerResource() throws IOException {
        responses.put(
                "resources/list",
                "{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"resources\":["
                        + "{\"uri\":\"zap://alerts\"},"
                        + "{\"uri\":\"zap://history\"}"
                        + "]}}");

        ImportResults results = importer.importServer(new ImportConfig(SERVER_URL, null));

        assertThat(results.requestCount(), is(7)); // 5 base + 2 resources/read
        assertThat(findAllRequestsByMethod("resources/read"), hasSize(2));
    }

    // ---- prompts ----

    @Test
    void shouldSendPromptsGetForEachDiscoveredPrompt() throws IOException {
        responses.put("prompts/list", promptsListResponse("baseline_scan", List.of("target")));

        ImportResults results = importer.importServer(new ImportConfig(SERVER_URL, null));

        assertThat(results.requestCount(), is(6)); // 5 base + 1 prompts/get
        HttpMessage getMsg = findRequestByMethod("prompts/get");
        assertThat(getMsg, is(notNullValue()));
        assertThat(
                parseBody(getMsg).path("params").path("name").asText(), equalTo("baseline_scan"));
    }

    @Test
    void shouldSendTemplatePlaceholderForEachPromptArgument() throws IOException {
        responses.put("prompts/list", promptsListResponse("scan", List.of("target", "config")));

        importer.importServer(new ImportConfig(SERVER_URL, null));

        JsonNode args =
                parseBody(findRequestByMethod("prompts/get")).path("params").path("arguments");
        assertThat(args.path("target").asText(), equalTo("{target}"));
        assertThat(args.path("config").asText(), equalTo("{config}"));
    }

    // ---- non-fatal failures in list calls ----

    @Test
    void shouldContinueWhenToolsListFails() throws IOException {
        willAnswer(
                        inv -> {
                            HttpMessage msg = inv.getArgument(0);
                            capturedRequests.add(msg);
                            JsonNode json = MAPPER.readTree(msg.getRequestBody().toString());
                            String method = json.path("method").asText();
                            if ("tools/list".equals(method)) {
                                throw new IOException("connection reset");
                            }
                            String responseBody =
                                    responses.getOrDefault(
                                            method, "{\"jsonrpc\":\"2.0\",\"result\":{}}");
                            msg.setResponseHeader(
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n");
                            msg.setResponseBody(responseBody);
                            return null;
                        })
                .given(sender)
                .sendAndReceive(any(HttpMessage.class));

        ImportResults results = importer.importServer(new ImportConfig(SERVER_URL, null));

        assertThat(results.errors(), not(empty()));
        assertThat(results.errors().get(0), containsString("tools/list"));
        // subsequent list calls must still have been attempted
        assertThat(findRequestByMethod("resources/list"), is(notNullValue()));
        assertThat(findRequestByMethod("prompts/list"), is(notNullValue()));
    }

    // ---- helpers ----

    private HttpMessage findRequestByMethod(String method) {
        return findAllRequestsByMethod(method).stream().findFirst().orElse(null);
    }

    private List<HttpMessage> findAllRequestsByMethod(String method) {
        List<HttpMessage> result = new ArrayList<>();
        for (HttpMessage msg : capturedRequests) {
            try {
                if (method.equals(
                        MAPPER.readTree(msg.getRequestBody().toString()).path("method").asText())) {
                    result.add(msg);
                }
            } catch (Exception ignored) {
            }
        }
        return result;
    }

    private static JsonNode parseBody(HttpMessage msg) {
        try {
            return MAPPER.readTree(msg.getRequestBody().toString());
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse request body", e);
        }
    }

    private static String toolsListResponse(String toolName, String inputSchema) {
        return "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\""
                + toolName
                + "\",\"inputSchema\":"
                + inputSchema
                + "}]}}";
    }

    private static String schemaWithStringProp(String propName) {
        return "{\"type\":\"object\",\"properties\":{\"" + propName + "\":{\"type\":\"string\"}}}";
    }

    private static String promptsListResponse(String promptName, List<String> args) {
        StringBuilder argsJson = new StringBuilder("[");
        for (int i = 0; i < args.size(); i++) {
            if (i > 0) {
                argsJson.append(",");
            }
            argsJson.append("{\"name\":\"").append(args.get(i)).append("\"}");
        }
        argsJson.append("]");
        return "{\"jsonrpc\":\"2.0\",\"id\":4,\"result\":{\"prompts\":[{\"name\":\""
                + promptName
                + "\",\"arguments\":"
                + argsJson
                + "}]}}";
    }
}
