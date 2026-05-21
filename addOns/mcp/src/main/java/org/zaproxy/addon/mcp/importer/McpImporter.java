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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.commonlib.ExtensionCommonlib;
import org.zaproxy.addon.commonlib.ValueProvider;
import org.zaproxy.zap.utils.ThreadUtils;

/**
 * Imports an MCP server by probing all of its accessible endpoints (initialize, tools, resources,
 * prompts) and recording every request/response in the ZAP history and sites tree.
 */
public class McpImporter {

    private static final Logger LOGGER = LogManager.getLogger(McpImporter.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String PROTOCOL_VERSION = "2024-11-05";
    private static final String CONTENT_TYPE = "application/json; charset=UTF-8";
    private static final String ACCEPT = "application/json, text/event-stream";
    private static final String SESSION_HEADER = "Mcp-Session-Id";
    // Bounds how many pages of any paginated list (tools/list, resources/list, prompts/list,
    // resources/templates/list) the importer will follow before giving up — guards against
    // misbehaving servers that never clear nextCursor.
    private static final int MAX_LIST_PAGES = 50;
    private static final java.util.regex.Pattern URI_TEMPLATE_VAR =
            java.util.regex.Pattern.compile("\\{([^}/]+)\\}");

    /** Configuration for a single import run. */
    public record ImportConfig(String serverUrl, String securityKey) {}

    /** Results of a completed import run. */
    public record ImportResults(int requestCount, List<String> errors) {}

    /**
     * Network abstraction used to send each MCP request. The default implementation calls ZAP's
     * {@link HttpSender#sendAndReceive(HttpMessage)} and, for {@code text/event-stream} responses,
     * drains the SSE body via {@link EventStreams#consumeBody(HttpMessage)} — required for the MCP
     * Streamable HTTP transport, which embeds JSON-RPC responses inside short-lived SSE frames.
     */
    @FunctionalInterface
    public interface NetworkClient {
        void send(HttpMessage msg) throws IOException;
    }

    private final ExtensionHistory extHistory;
    private final NetworkClient networkClient;
    private final ValueProvider valueProvider;

    public McpImporter() {
        this.extHistory =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionHistory.class);
        HttpSender sender = new HttpSender(HttpSender.MANUAL_REQUEST_INITIATOR);
        this.networkClient =
                msg -> {
                    sender.sendAndReceive(msg);
                    EventStreams.consumeBody(msg);
                };
        this.valueProvider =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionCommonlib.class)
                        .getValueProvider();
    }

    /**
     * Constructor for testing — accepts a custom {@link NetworkClient} and optional {@link
     * ValueProvider} to avoid ZAP infrastructure.
     */
    McpImporter(NetworkClient networkClient, ValueProvider valueProvider) {
        this.extHistory = null;
        this.networkClient = networkClient;
        this.valueProvider = valueProvider;
    }

    /**
     * Probes the MCP server at the given URL, sending requests for every method (initialize,
     * tools/list, resources/list, prompts/list, plus one request per tool/resource/prompt). All
     * HTTP transactions are recorded in ZAP's history and sites tree.
     */
    public ImportResults importServer(ImportConfig config) {

        String rawUrl = config.serverUrl();
        if (rawUrl == null || rawUrl.isBlank()) {
            return new ImportResults(
                    0, List.of(Constant.messages.getString("mcp.importserver.error.emptyurl")));
        }
        String rawUrlLower = rawUrl.toLowerCase();
        if (!rawUrlLower.startsWith("http://") && !rawUrlLower.startsWith("https://")) {
            return new ImportResults(
                    0, List.of(Constant.messages.getString("mcp.importserver.error.nohttp")));
        }

        URI serverUri;
        try {
            serverUri = new URI(rawUrl, true);
        } catch (URIException e) {
            return new ImportResults(
                    0,
                    List.of(
                            Constant.messages.getString(
                                    "mcp.importserver.error.badurl", e.getMessage())));
        }

        // 1. initialize — abort if this fails
        AtomicInteger idCounter = new AtomicInteger(1);
        List<String> errors = new ArrayList<>();
        ObjectNode initParams = MAPPER.createObjectNode();
        initParams.put("protocolVersion", PROTOCOL_VERSION);
        initParams.putObject("capabilities");
        ObjectNode clientInfo = initParams.putObject("clientInfo");
        clientInfo.put("name", "ZAP MCP Importer");
        clientInfo.put("version", "1.0.0");

        String securityKey = config.securityKey();
        HttpMessage initMsg =
                sendAndRecord(
                        serverUri, "initialize", initParams, securityKey, null, idCounter, errors);
        if (initMsg == null) {
            return new ImportResults(0, errors);
        }
        int requestCount = 1;

        int status = initMsg.getResponseHeader().getStatusCode();
        if (status < 200 || status >= 300) {
            errors.add(Constant.messages.getString("mcp.importserver.error.badstatus", status));
            return new ImportResults(requestCount, errors);
        }
        if (hasJsonRpcError(initMsg)) {
            errors.add(
                    Constant.messages.getString(
                            "mcp.importserver.error.badinit", getJsonRpcErrorMessage(initMsg)));
            return new ImportResults(requestCount, errors);
        }
        if (!isValidMcpInitializeResult(initMsg)) {
            errors.add(Constant.messages.getString("mcp.importserver.error.handshakefailed"));
            return new ImportResults(requestCount, errors);
        }

        String sessionId = initMsg.getResponseHeader().getHeader(SESSION_HEADER);
        JsonNode capabilities = readJsonRpcPayload(initMsg).path("result").path("capabilities");

        // 1b. notifications/initialized — completes the initialization phase
        if (sendNotification(serverUri, "notifications/initialized", securityKey, sessionId)) {
            requestCount++;
        }

        // 1c. ping — every conformant MCP server supports this; gives a cheap liveness signal.
        if (sendAndRecord(serverUri, "ping", null, securityKey, sessionId, idCounter, errors)
                != null) {
            requestCount++;
        }

        // 1d. logging/setLevel — only call when the server advertises the logging capability.
        if (capabilities.has("logging")) {
            ObjectNode logParams = MAPPER.createObjectNode();
            logParams.put("level", "info");
            if (sendAndRecord(
                            serverUri,
                            "logging/setLevel",
                            logParams,
                            securityKey,
                            sessionId,
                            idCounter,
                            errors)
                    != null) {
                requestCount++;
            }
        }

        // 2. tools/list (paginated)
        List<ToolDef> tools = new ArrayList<>();
        List<HttpMessage> toolsPages =
                listAllPages(serverUri, "tools/list", securityKey, sessionId, idCounter, errors);
        requestCount += toolsPages.size();
        for (HttpMessage page : toolsPages) {
            tools.addAll(extractToolDefs(page));
        }

        // 3. resources/list (paginated)
        List<String> resourceUris = new ArrayList<>();
        List<HttpMessage> resourcePages =
                listAllPages(
                        serverUri, "resources/list", securityKey, sessionId, idCounter, errors);
        requestCount += resourcePages.size();
        for (HttpMessage page : resourcePages) {
            resourceUris.addAll(extractStringArray(page, "result", "resources", "uri"));
        }

        // 4. resources/templates/list (paginated) — many servers expose parametric URIs here.
        List<String> templateUris = new ArrayList<>();
        List<HttpMessage> templatePages =
                listAllPages(
                        serverUri,
                        "resources/templates/list",
                        securityKey,
                        sessionId,
                        idCounter,
                        errors);
        requestCount += templatePages.size();
        for (HttpMessage page : templatePages) {
            templateUris.addAll(
                    extractStringArray(page, "result", "resourceTemplates", "uriTemplate"));
        }

        // 5. prompts/list (paginated)
        List<PromptDef> prompts = new ArrayList<>();
        List<HttpMessage> promptPages =
                listAllPages(serverUri, "prompts/list", securityKey, sessionId, idCounter, errors);
        requestCount += promptPages.size();
        for (HttpMessage page : promptPages) {
            prompts.addAll(extractPromptDefs(page));
        }

        // 6. resources/read for each discovered resource
        for (String uri : resourceUris) {
            ObjectNode params = MAPPER.createObjectNode();
            params.put("uri", uri);
            HttpMessage msg =
                    sendAndRecord(
                            serverUri,
                            "resources/read",
                            params,
                            securityKey,
                            sessionId,
                            idCounter,
                            errors);
            if (msg != null) {
                requestCount++;
            }
        }

        // 7. resources/read for each resource template, with {var} placeholders resolved.
        for (String template : templateUris) {
            String resolved = resolveUriTemplate(template, serverUri);
            ObjectNode params = MAPPER.createObjectNode();
            params.put("uri", resolved);
            HttpMessage msg =
                    sendAndRecord(
                            serverUri,
                            "resources/read",
                            params,
                            securityKey,
                            sessionId,
                            idCounter,
                            errors);
            if (msg != null) {
                requestCount++;
            }
        }

        // 8. tools/call for each tool with schema-derived placeholder arguments
        for (ToolDef tool : tools) {
            ObjectNode params = MAPPER.createObjectNode();
            params.put("name", tool.name());
            params.set("arguments", buildToolArguments(tool.inputSchema(), serverUri));
            HttpMessage msg =
                    sendAndRecord(
                            serverUri,
                            "tools/call",
                            params,
                            securityKey,
                            sessionId,
                            idCounter,
                            errors);
            if (msg != null) {
                requestCount++;
            }
        }

        // 9. prompts/get for each prompt with schema-derived placeholder arguments
        for (PromptDef prompt : prompts) {
            ObjectNode params = MAPPER.createObjectNode();
            params.put("name", prompt.name());
            params.set("arguments", buildPromptArguments(prompt.arguments(), serverUri));
            HttpMessage msg =
                    sendAndRecord(
                            serverUri,
                            "prompts/get",
                            params,
                            securityKey,
                            sessionId,
                            idCounter,
                            errors);
            if (msg != null) {
                requestCount++;
            }
        }

        return new ImportResults(requestCount, errors);
    }

    /**
     * Calls a paginated MCP list method, following {@code nextCursor} up to {@link #MAX_LIST_PAGES}
     * pages, and returns the response message from each page. Aborts the loop on the first failed
     * page so the caller can still process what came before.
     */
    private List<HttpMessage> listAllPages(
            URI serverUri,
            String method,
            String securityKey,
            String sessionId,
            AtomicInteger idCounter,
            List<String> errors) {
        List<HttpMessage> pages = new ArrayList<>();
        String cursor = null;
        for (int i = 0; i < MAX_LIST_PAGES; i++) {
            ObjectNode params = null;
            if (cursor != null) {
                params = MAPPER.createObjectNode();
                params.put("cursor", cursor);
            }
            HttpMessage page =
                    sendAndRecord(
                            serverUri, method, params, securityKey, sessionId, idCounter, errors);
            if (page == null) {
                break;
            }
            pages.add(page);
            JsonNode next = readJsonRpcPayload(page).path("result").path("nextCursor");
            if (next.isMissingNode() || next.isNull() || next.asText().isEmpty()) {
                break;
            }
            cursor = next.asText();
        }
        return pages;
    }

    /**
     * Replaces RFC 6570 {@code {var}} placeholders in a resource template URI with values from the
     * {@link ValueProvider}. Falls back to the variable name if no provider is configured.
     */
    private String resolveUriTemplate(String template, URI serverUri) {
        java.util.regex.Matcher matcher = URI_TEMPLATE_VAR.matcher(template);
        StringBuilder out = new StringBuilder();
        while (matcher.find()) {
            String var = matcher.group(1);
            String value = resolveStringValue(serverUri, var, "string");
            if (value == null || value.isEmpty()) {
                value = var;
            }
            matcher.appendReplacement(out, java.util.regex.Matcher.quoteReplacement(value));
        }
        matcher.appendTail(out);
        return out.toString();
    }

    /**
     * Sends a JSON-RPC notification (no {@code id} field) and records it in history. Notifications
     * do not carry a response body, so the recorded message captures the server's acknowledgement
     * (typically HTTP 202) without attempting to parse a JSON-RPC result.
     *
     * @return {@code true} if the notification was sent successfully, {@code false} otherwise
     */
    private boolean sendNotification(
            URI serverUri, String method, String securityKey, String sessionId) {
        HttpMessage msg = buildNotification(serverUri, method, securityKey, sessionId);
        if (msg == null) {
            return false;
        }
        try {
            networkClient.send(msg);
        } catch (IOException e) {
            LOGGER.warn("MCP notification failed for method {}: {}", method, e.getMessage());
            return false;
        }
        recordMessage(msg);
        return true;
    }

    private HttpMessage buildNotification(
            URI serverUri, String method, String securityKey, String sessionId) {
        try {
            ObjectNode body = MAPPER.createObjectNode();
            body.put("jsonrpc", "2.0");
            body.put("method", method);

            HttpMessage msg = new HttpMessage(serverUri);
            applyCommonRequestHeaders(msg, securityKey, sessionId);

            String bodyStr = MAPPER.writeValueAsString(body);
            msg.setRequestBody(bodyStr);
            msg.getRequestHeader().setContentLength(msg.getRequestBody().length());
            return msg;
        } catch (Exception e) {
            LOGGER.warn(
                    "Failed to build MCP notification for method {}: {}", method, e.getMessage());
            return null;
        }
    }

    private HttpMessage sendAndRecord(
            URI serverUri,
            String method,
            ObjectNode paramsNode,
            String securityKey,
            String sessionId,
            AtomicInteger idCounter,
            List<String> errors) {
        HttpMessage msg =
                buildRequest(serverUri, method, paramsNode, securityKey, sessionId, idCounter);
        if (msg == null) {
            return null;
        }
        try {
            networkClient.send(msg);
        } catch (IOException e) {
            errors.add(
                    Constant.messages.getString(
                            "mcp.importserver.error.request", method, e.getMessage()));
            LOGGER.debug("MCP request failed for method {}: {}", method, e.getMessage());
            return null;
        }
        recordMessage(msg);
        return msg;
    }

    private HttpMessage buildRequest(
            URI serverUri,
            String method,
            ObjectNode paramsNode,
            String securityKey,
            String sessionId,
            AtomicInteger idCounter) {
        try {
            ObjectNode body = MAPPER.createObjectNode();
            body.put("jsonrpc", "2.0");
            body.put("id", idCounter.getAndIncrement());
            body.put("method", method);
            if (paramsNode != null) {
                body.set("params", paramsNode);
            }

            HttpMessage msg = new HttpMessage(serverUri);
            applyCommonRequestHeaders(msg, securityKey, sessionId);

            String bodyStr = MAPPER.writeValueAsString(body);
            msg.setRequestBody(bodyStr);
            msg.getRequestHeader().setContentLength(msg.getRequestBody().length());
            return msg;
        } catch (Exception e) {
            LOGGER.warn("Failed to build MCP request for method {}: {}", method, e.getMessage());
            return null;
        }
    }

    private static void applyCommonRequestHeaders(
            HttpMessage msg, String securityKey, String sessionId) {
        msg.getRequestHeader().setMethod(HttpRequestHeader.POST);
        msg.getRequestHeader().setHeader(HttpHeader.CONTENT_TYPE, CONTENT_TYPE);
        msg.getRequestHeader().setHeader("Accept", ACCEPT);
        if (securityKey != null && !securityKey.isBlank()) {
            msg.getRequestHeader().setHeader("Authorization", securityKey);
        }
        if (sessionId != null && !sessionId.isBlank()) {
            msg.getRequestHeader().setHeader(SESSION_HEADER, sessionId);
        }
    }

    private void recordMessage(HttpMessage msg) {
        try {
            HistoryReference histRef =
                    new HistoryReference(
                            Model.getSingleton().getSession(), HistoryReference.TYPE_ZAP_USER, msg);
            ThreadUtils.invokeAndWaitHandled(
                    () -> {
                        if (extHistory != null) {
                            extHistory.addHistory(histRef);
                        }
                        Model.getSingleton().getSession().getSiteTree().addPath(histRef, msg);
                    });
        } catch (Exception e) {
            LOGGER.warn("Failed to record MCP message in history: {}", e.getMessage(), e);
        }
    }

    /**
     * Parses the JSON-RPC payload from a response. The Streamable HTTP transport allows the server
     * to reply either with a single JSON object or with an SSE stream carrying a single JSON-RPC
     * message (possibly split across multiple {@code data:} lines, joined with {@code \n} per the
     * SSE spec). Returns a {@link com.fasterxml.jackson.databind.node.MissingNode} if the body
     * cannot be parsed.
     */
    private JsonNode readJsonRpcPayload(HttpMessage msg) {
        String body = msg.getResponseBody().toString();
        String contentType = msg.getResponseHeader().getHeader(HttpHeader.CONTENT_TYPE);
        try {
            if (contentType != null
                    && contentType.toLowerCase(Locale.ROOT).contains("text/event-stream")) {
                StringBuilder data = new StringBuilder();
                for (String line : body.split("\\R")) {
                    if (line.startsWith("data:")) {
                        if (data.length() > 0) {
                            data.append('\n');
                        }
                        data.append(line.substring(5).stripLeading());
                    }
                }
                if (data.length() == 0) {
                    return MAPPER.missingNode();
                }
                return MAPPER.readTree(data.toString());
            }
            return MAPPER.readTree(body);
        } catch (Exception e) {
            LOGGER.warn("Failed to parse MCP response body: {}", e.getMessage());
            return MAPPER.missingNode();
        }
    }

    private boolean isValidMcpInitializeResult(HttpMessage msg) {
        JsonNode result = readJsonRpcPayload(msg).get("result");
        return result != null && result.has("protocolVersion");
    }

    private boolean hasJsonRpcError(HttpMessage msg) {
        return readJsonRpcPayload(msg).has("error");
    }

    private String getJsonRpcErrorMessage(HttpMessage msg) {
        JsonNode error = readJsonRpcPayload(msg).get("error");
        if (error != null && error.has("message")) {
            return error.get("message").asText();
        }
        return "Unknown error";
    }

    /** Holds the name and input schema of a discovered tool. */
    private record ToolDef(String name, JsonNode inputSchema) {}

    /** Holds the name and argument names of a discovered prompt. */
    private record PromptDef(String name, List<String> arguments) {}

    /** Parses the {@code tools/list} response into {@link ToolDef} objects. */
    private List<ToolDef> extractToolDefs(HttpMessage msg) {
        List<ToolDef> tools = new ArrayList<>();
        JsonNode toolsNode = readJsonRpcPayload(msg).path("result").path("tools");
        if (toolsNode.isArray()) {
            for (JsonNode tool : toolsNode) {
                String name = tool.path("name").asText(null);
                if (name != null) {
                    tools.add(new ToolDef(name, tool.path("inputSchema")));
                }
            }
        }
        return tools;
    }

    /** Parses the {@code prompts/list} response into {@link PromptDef} objects. */
    private List<PromptDef> extractPromptDefs(HttpMessage msg) {
        List<PromptDef> prompts = new ArrayList<>();
        JsonNode promptsNode = readJsonRpcPayload(msg).path("result").path("prompts");
        if (promptsNode.isArray()) {
            for (JsonNode prompt : promptsNode) {
                String name = prompt.path("name").asText(null);
                if (name != null) {
                    List<String> argNames = new ArrayList<>();
                    JsonNode args = prompt.path("arguments");
                    if (args.isArray()) {
                        for (JsonNode arg : args) {
                            String argName = arg.path("name").asText(null);
                            if (argName != null) {
                                argNames.add(argName);
                            }
                        }
                    }
                    prompts.add(new PromptDef(name, argNames));
                }
            }
        }
        return prompts;
    }

    /**
     * Builds an {@code arguments} object for a {@code tools/call} request. For each string-typed
     * property the value is resolved via the {@link ValueProvider} (which can supply realistic
     * defaults based on the field name); non-string types receive a typed zero/false/empty default.
     */
    private ObjectNode buildToolArguments(JsonNode inputSchema, URI serverUri) {
        ObjectNode args = MAPPER.createObjectNode();
        if (inputSchema == null || !inputSchema.isObject()) {
            return args;
        }
        JsonNode properties = inputSchema.path("properties");
        if (!properties.isObject()) {
            return args;
        }
        properties
                .properties()
                .forEach(
                        entry -> {
                            String paramName = entry.getKey();
                            String type = entry.getValue().path("type").asText("string");
                            switch (type) {
                                case "integer", "number" -> args.put(paramName, 0);
                                case "boolean" -> args.put(paramName, false);
                                case "array" -> args.putArray(paramName);
                                case "object" -> args.putObject(paramName);
                                default ->
                                        args.put(
                                                paramName,
                                                resolveStringValue(serverUri, paramName, type));
                            }
                        });
        return args;
    }

    /**
     * Builds an {@code arguments} object for a {@code prompts/get} request. Each argument value is
     * resolved via the {@link ValueProvider}.
     */
    private ObjectNode buildPromptArguments(List<String> argumentNames, URI serverUri) {
        ObjectNode args = MAPPER.createObjectNode();
        for (String name : argumentNames) {
            args.put(name, resolveStringValue(serverUri, name, "string"));
        }
        return args;
    }

    /**
     * Resolves a value for a string-typed field using the {@link ValueProvider}. An empty string is
     * passed as the default so the provider either generates a meaningful value or returns {@code
     * ""} — never a raw template token with curly braces. Falls back to an empty string when no
     * provider is available.
     */
    private String resolveStringValue(URI serverUri, String fieldName, String fieldType) {
        if (valueProvider == null) {
            return fieldName;
        }
        return valueProvider.getValue(
                serverUri,
                serverUri.toString(),
                fieldName,
                fieldName,
                List.of(),
                Map.of(),
                Map.of("type", fieldType));
    }

    /**
     * Navigates a JSON response body through the given path elements (all but the last), then
     * collects the named field (the last element) from each item in the resulting array.
     *
     * <p>Example: {@code extractStringArray(msg, "result", "tools", "name")} navigates to {@code
     * result.tools} and returns the {@code name} field from each array element.
     */
    private List<String> extractStringArray(HttpMessage msg, String... path) {
        List<String> result = new ArrayList<>();
        JsonNode node = readJsonRpcPayload(msg);
        for (int i = 0; i < path.length - 1; i++) {
            if (node == null || !node.has(path[i])) {
                return result;
            }
            node = node.get(path[i]);
        }
        String fieldName = path[path.length - 1];
        if (node != null && node.isArray()) {
            for (JsonNode item : node) {
                if (item.has(fieldName)) {
                    result.add(item.get(fieldName).asText());
                }
            }
        }
        return result;
    }
}
