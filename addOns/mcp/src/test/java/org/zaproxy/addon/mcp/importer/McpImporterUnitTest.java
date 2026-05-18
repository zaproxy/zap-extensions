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
import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.commonlib.ValueProvider;
import org.zaproxy.addon.mcp.importer.McpImporter.ImportConfig;
import org.zaproxy.addon.mcp.importer.McpImporter.ImportResults;
import org.zaproxy.zap.utils.I18N;

/** Unit tests for {@link McpImporter}. */
class McpImporterUnitTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String SERVER_URL = "http://localhost:8282/mcp";

    @BeforeAll
    static void setUpMessages() {
        Constant.messages = new I18N(Locale.ROOT);
    }

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
        importer = new McpImporter(sender, null);
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
        // Given

        // When
        ImportResults results = importer.importServer(new ImportConfig("not a valid url %%", null));

        // Then
        assertThat(results.requestCount(), is(0));
        assertThat(results.errors(), hasSize(1));
        assertThat(results.errors().get(0), is("!mcp.importserver.error.nohttp!"));
        verify(sender, never()).sendAndReceive(any(HttpMessage.class));
    }

    // ---- initialize failure — aborts immediately ----

    @Test
    void shouldStopOnInitializeIoFailure() throws IOException {
        // Given
        willThrow(new IOException("connection refused"))
                .given(sender)
                .sendAndReceive(any(HttpMessage.class));

        // When
        ImportResults results = importer.importServer(new ImportConfig(SERVER_URL, null));

        // Then
        assertThat(results.requestCount(), is(0));
        assertThat(results.errors(), not(empty()));
        assertThat(results.errors().get(0), is("!mcp.importserver.error.request!"));
    }

    @Test
    void shouldStopOnInitializeHttpError() throws IOException {
        // Given
        willAnswer(
                        inv -> {
                            HttpMessage msg = inv.getArgument(0);
                            msg.setResponseHeader("HTTP/1.1 401 Unauthorized\r\n\r\n");
                            msg.setResponseBody("");
                            return null;
                        })
                .given(sender)
                .sendAndReceive(any(HttpMessage.class));

        // When
        ImportResults results = importer.importServer(new ImportConfig(SERVER_URL, null));

        // Then
        assertThat(results.requestCount(), is(1));
        assertThat(results.errors(), not(empty()));
        assertThat(results.errors().get(0), is("!mcp.importserver.error.badstatus!"));
        assertThat(findRequestByMethod("tools/list"), is(nullValue()));
    }

    @Test
    void shouldStopOnInitializeJsonRpcError() throws IOException {
        // Given
        responses.put(
                "initialize",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32600,\"message\":\"Unauthorized\"}}");

        // When
        ImportResults results = importer.importServer(new ImportConfig(SERVER_URL, null));

        // Then
        assertThat(results.requestCount(), is(1));
        assertThat(results.errors(), not(empty()));
        assertThat(results.errors().get(0), is("!mcp.importserver.error.badinit!"));
        assertThat(findRequestByMethod("tools/list"), is(nullValue()));
    }

    @Test
    void shouldStopWhenInitializeResponseIsNotValidMcp() throws IOException {
        // Given — simulate a standard website returning HTML
        responses.put("initialize", "<html><body>Not an MCP server</body></html>");

        // When
        ImportResults results = importer.importServer(new ImportConfig(SERVER_URL, null));

        // Then
        // I18N(Locale.ROOT) returns !key! for addon messages, so we check the key name
        assertThat(results.requestCount(), is(1));
        assertThat(results.errors(), hasSize(1));
        assertThat(results.errors().get(0), containsString("handshakefailed"));
        assertThat(findRequestByMethod("tools/list"), is(nullValue()));
    }

    @Test
    void shouldStopWhenInitializeResponseHasNoProtocolVersion() throws IOException {
        // Given — valid JSON but not an MCP response
        responses.put(
                "initialize",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"someField\":\"value\"}}");

        // When
        ImportResults results = importer.importServer(new ImportConfig(SERVER_URL, null));

        // Then
        // I18N(Locale.ROOT) returns !key! for addon messages, so we check the key name
        assertThat(results.requestCount(), is(1));
        assertThat(results.errors(), hasSize(1));
        assertThat(results.errors().get(0), containsString("handshakefailed"));
        assertThat(findRequestByMethod("tools/list"), is(nullValue()));
    }

    // ---- happy path ----

    @Test
    void shouldCountFiveRequestsForMinimalSuccessfulImport() throws IOException {
        // Given

        // When
        ImportResults results = importer.importServer(new ImportConfig(SERVER_URL, null));

        // Then - initialize + notifications/initialized + tools/list + resources/list +
        // prompts/list
        assertThat(results.errors(), is(empty()));
        assertThat(results.requestCount(), is(5));
    }

    @Test
    void shouldIncludeAllFiveMethodsInMinimalImport() throws IOException {
        // Given

        // When
        importer.importServer(new ImportConfig(SERVER_URL, null));

        // Then
        assertThat(findRequestByMethod("initialize"), is(notNullValue()));
        assertThat(findRequestByMethod("notifications/initialized"), is(notNullValue()));
        assertThat(findRequestByMethod("tools/list"), is(notNullValue()));
        assertThat(findRequestByMethod("resources/list"), is(notNullValue()));
        assertThat(findRequestByMethod("prompts/list"), is(notNullValue()));
    }

    // ---- request structure ----

    @Test
    void shouldSendInitializeWithCorrectJsonRpcEnvelope() throws IOException {
        // Given

        // When
        importer.importServer(new ImportConfig(SERVER_URL, null));

        // Then
        HttpMessage msg = findRequestByMethod("initialize");
        JsonNode body = parseBody(msg);
        assertThat(body.path("jsonrpc").asText(), equalTo("2.0"));
        assertThat(body.has("id"), is(true));
        assertThat(body.path("method").asText(), equalTo("initialize"));
    }

    @Test
    void shouldSendInitializeWithProtocolVersionAndClientInfo() throws IOException {
        // Given

        // When
        importer.importServer(new ImportConfig(SERVER_URL, null));

        // Then
        JsonNode params = parseBody(findRequestByMethod("initialize")).path("params");
        assertThat(params.path("protocolVersion").asText(), equalTo("2024-11-05"));
        assertThat(params.path("clientInfo").path("name").asText(), equalTo("ZAP MCP Importer"));
    }

    @Test
    void shouldSendNotificationWithoutIdField() throws IOException {
        // Given

        // When
        importer.importServer(new ImportConfig(SERVER_URL, null));

        // Then
        JsonNode body = parseBody(findRequestByMethod("notifications/initialized"));
        assertThat(body.has("id"), is(false));
        assertThat(body.path("jsonrpc").asText(), equalTo("2.0"));
    }

    // ---- security key ----

    @Test
    void shouldSetAuthorizationHeaderOnAllRequestsWhenSecurityKeyProvided() throws IOException {
        // Given

        // When
        importer.importServer(new ImportConfig(SERVER_URL, "Bearer secret-key"));

        // Then
        assertThat(capturedRequests, not(empty()));
        for (HttpMessage msg : capturedRequests) {
            assertThat(
                    msg.getRequestHeader().getHeader("Authorization"),
                    equalTo("Bearer secret-key"));
        }
    }

    @Test
    void shouldNotSetAuthorizationHeaderWhenSecurityKeyIsNull() throws IOException {
        // Given

        // When
        importer.importServer(new ImportConfig(SERVER_URL, null));

        // Then
        for (HttpMessage msg : capturedRequests) {
            assertThat(msg.getRequestHeader().getHeader("Authorization"), is(nullValue()));
        }
    }

    @Test
    void shouldNotSetAuthorizationHeaderWhenSecurityKeyIsBlank() throws IOException {
        // Given

        // When
        importer.importServer(new ImportConfig(SERVER_URL, "   "));

        // Then
        for (HttpMessage msg : capturedRequests) {
            assertThat(msg.getRequestHeader().getHeader("Authorization"), is(nullValue()));
        }
    }

    // ---- tools ----

    @Test
    void shouldSendToolsCallForEachDiscoveredTool() throws IOException {
        // Given
        responses.put(
                "tools/list", toolsListResponse("scan_target", schemaWithStringProp("target")));
        responses.put("tools/call", "{\"jsonrpc\":\"2.0\",\"id\":6,\"result\":{\"content\":[]}}");

        // When
        ImportResults results = importer.importServer(new ImportConfig(SERVER_URL, null));

        // Then
        assertThat(results.requestCount(), is(6)); // 5 base + 1 tools/call
        HttpMessage toolsCallMsg = findRequestByMethod("tools/call");
        assertThat(toolsCallMsg, is(notNullValue()));
        assertThat(
                parseBody(toolsCallMsg).path("params").path("name").asText(),
                equalTo("scan_target"));
    }

    @Test
    void shouldSendOneToolsCallPerTool() throws IOException {
        // Given
        responses.put(
                "tools/list",
                "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":["
                        + "{\"name\":\"tool_a\",\"inputSchema\":{}},"
                        + "{\"name\":\"tool_b\",\"inputSchema\":{}}"
                        + "]}}");

        // When
        ImportResults results = importer.importServer(new ImportConfig(SERVER_URL, null));

        // Then
        assertThat(results.requestCount(), is(7)); // 5 base + 2 tools/call
        assertThat(findAllRequestsByMethod("tools/call"), hasSize(2));
    }

    @Test
    void shouldUseFieldNameAsDefaultForStringSchemaPropertiesWhenNoValueProvider()
            throws IOException {
        // Given
        responses.put(
                "tools/list",
                toolsListResponse(
                        "spider",
                        "{\"type\":\"object\",\"properties\":{"
                                + "\"target\":{\"type\":\"string\"},"
                                + "\"scope\":{\"type\":\"string\"}"
                                + "}}"));

        // When
        importer.importServer(new ImportConfig(SERVER_URL, null));

        // Then
        JsonNode args =
                parseBody(findRequestByMethod("tools/call")).path("params").path("arguments");
        assertThat(args.path("target").asText(), equalTo("target"));
        assertThat(args.path("scope").asText(), equalTo("scope"));
    }

    @Test
    void shouldUseValueProviderForStringSchemaProperties() throws IOException {
        // Given
        ValueProvider valueProvider =
                mock(ValueProvider.class, withSettings().strictness(Strictness.LENIENT));
        willAnswer(inv -> "generated-" + inv.getArgument(2))
                .given(valueProvider)
                .getValue(any(), any(), any(), any(), any(), any(), any());
        importer = new McpImporter(sender, valueProvider);
        responses.put(
                "tools/list",
                toolsListResponse(
                        "spider",
                        "{\"type\":\"object\",\"properties\":{"
                                + "\"target\":{\"type\":\"string\"},"
                                + "\"scope\":{\"type\":\"string\"}"
                                + "}}"));

        // When
        importer.importServer(new ImportConfig(SERVER_URL, null));

        // Then - values come from the provider, no raw {token} strings
        JsonNode args =
                parseBody(findRequestByMethod("tools/call")).path("params").path("arguments");
        assertThat(args.path("target").asText(), equalTo("generated-target"));
        assertThat(args.path("scope").asText(), equalTo("generated-scope"));
    }

    @Test
    void shouldUseTypedDefaultsForNonStringSchemaProperties() throws IOException {
        // Given
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

        // When
        importer.importServer(new ImportConfig(SERVER_URL, null));

        // Then
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
        // Given
        responses.put(
                "resources/list",
                "{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"resources\":[{\"uri\":\"zap://alerts\"}]}}");

        // When
        ImportResults results = importer.importServer(new ImportConfig(SERVER_URL, null));

        // Then
        assertThat(results.requestCount(), is(6)); // 5 base + 1 resources/read
        HttpMessage readMsg = findRequestByMethod("resources/read");
        assertThat(readMsg, is(notNullValue()));
        assertThat(parseBody(readMsg).path("params").path("uri").asText(), equalTo("zap://alerts"));
    }

    @Test
    void shouldSendOneResourcesReadPerResource() throws IOException {
        // Given
        responses.put(
                "resources/list",
                "{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"resources\":["
                        + "{\"uri\":\"zap://alerts\"},"
                        + "{\"uri\":\"zap://history\"}"
                        + "]}}");

        // When
        ImportResults results = importer.importServer(new ImportConfig(SERVER_URL, null));

        // Then
        assertThat(results.requestCount(), is(7)); // 5 base + 2 resources/read
        assertThat(findAllRequestsByMethod("resources/read"), hasSize(2));
    }

    // ---- prompts ----

    @Test
    void shouldSendPromptsGetForEachDiscoveredPrompt() throws IOException {
        // Given
        responses.put("prompts/list", promptsListResponse("baseline_scan", List.of("target")));

        // When
        ImportResults results = importer.importServer(new ImportConfig(SERVER_URL, null));

        // Then
        assertThat(results.requestCount(), is(6)); // 5 base + 1 prompts/get
        HttpMessage getMsg = findRequestByMethod("prompts/get");
        assertThat(getMsg, is(notNullValue()));
        assertThat(
                parseBody(getMsg).path("params").path("name").asText(), equalTo("baseline_scan"));
    }

    @Test
    void shouldUseFieldNameAsDefaultForPromptArgumentsWhenNoValueProvider() throws IOException {
        // Given
        responses.put("prompts/list", promptsListResponse("scan", List.of("target", "config")));

        // When
        importer.importServer(new ImportConfig(SERVER_URL, null));

        // Then
        JsonNode args =
                parseBody(findRequestByMethod("prompts/get")).path("params").path("arguments");
        assertThat(args.path("target").asText(), equalTo("target"));
        assertThat(args.path("config").asText(), equalTo("config"));
    }

    // ---- non-fatal failures in list calls ----

    @Test
    void shouldContinueWhenToolsListFails() throws IOException {
        // Given
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

        // When
        ImportResults results = importer.importServer(new ImportConfig(SERVER_URL, null));

        // Then
        assertThat(results.errors(), not(empty()));
        assertThat(results.errors().get(0), is("!mcp.importserver.error.request!"));
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
