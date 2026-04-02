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
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;
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

    /** Configuration for a single import run. */
    public record ImportConfig(String serverUrl, String securityKey) {}

    /** Results of a completed import run. */
    public record ImportResults(int requestCount, List<String> errors) {}

    private final ExtensionHistory extHistory;
    private final HttpSender httpSender;

    public McpImporter() {
        this.extHistory =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionHistory.class);
        this.httpSender = new HttpSender(HttpSender.MANUAL_REQUEST_INITIATOR);
    }

    /**
     * Constructor for testing — accepts a pre-built {@link HttpSender} to avoid ZAP infrastructure.
     */
    McpImporter(HttpSender httpSender) {
        this.extHistory = null;
        this.httpSender = httpSender;
    }

    /**
     * Probes the MCP server at the given URL, sending requests for every method (initialize,
     * tools/list, resources/list, prompts/list, plus one request per tool/resource/prompt). All
     * HTTP transactions are recorded in ZAP's history and sites tree.
     */
    public ImportResults importServer(ImportConfig config) {
        List<String> errors = new ArrayList<>();
        AtomicInteger idCounter = new AtomicInteger(1);
        int requestCount = 0;

        String rawUrl = config.serverUrl();
        if (rawUrl == null || rawUrl.isBlank()) {
            errors.add("Invalid server URL: URL is required");
            return new ImportResults(0, errors);
        }
        String rawUrlLower = rawUrl.toLowerCase();
        if (!rawUrlLower.startsWith("http://") && !rawUrlLower.startsWith("https://")) {
            errors.add("Invalid server URL: must be an http:// or https:// URL");
            return new ImportResults(0, errors);
        }

        URI serverUri;
        try {
            serverUri = new URI(rawUrl, false);
        } catch (URIException e) {
            errors.add("Invalid server URL: " + e.getMessage());
            return new ImportResults(0, errors);
        }

        // 1. initialize — abort if this fails
        ObjectNode initParams = MAPPER.createObjectNode();
        initParams.put("protocolVersion", PROTOCOL_VERSION);
        initParams.putObject("capabilities");
        ObjectNode clientInfo = initParams.putObject("clientInfo");
        clientInfo.put("name", "ZAP MCP Importer");
        clientInfo.put("version", "1.0.0");

        HttpMessage initMsg =
                sendAndRecord(
                        serverUri,
                        "initialize",
                        initParams,
                        config.securityKey(),
                        idCounter,
                        errors);
        if (initMsg == null) {
            return new ImportResults(requestCount, errors);
        }
        requestCount++;

        int status = initMsg.getResponseHeader().getStatusCode();
        if (status < 200 || status >= 300) {
            errors.add("MCP server returned HTTP " + status + " for initialize");
            return new ImportResults(requestCount, errors);
        }
        if (hasJsonRpcError(initMsg)) {
            errors.add("MCP initialize failed: " + getJsonRpcErrorMessage(initMsg));
            return new ImportResults(requestCount, errors);
        }

        // 1b. notifications/initialized — completes the initialization phase
        if (sendNotification(serverUri, "notifications/initialized", config.securityKey())) {
            requestCount++;
        }

        // 2. tools/list
        List<ToolDef> tools = new ArrayList<>();
        HttpMessage toolsListMsg =
                sendAndRecord(
                        serverUri, "tools/list", null, config.securityKey(), idCounter, errors);
        if (toolsListMsg != null) {
            requestCount++;
            tools = extractToolDefs(toolsListMsg);
        }

        // 3. resources/list
        List<String> resourceUris = new ArrayList<>();
        HttpMessage resourcesListMsg =
                sendAndRecord(
                        serverUri, "resources/list", null, config.securityKey(), idCounter, errors);
        if (resourcesListMsg != null) {
            requestCount++;
            resourceUris = extractStringArray(resourcesListMsg, "result", "resources", "uri");
        }

        // 4. prompts/list
        List<PromptDef> prompts = new ArrayList<>();
        HttpMessage promptsListMsg =
                sendAndRecord(
                        serverUri, "prompts/list", null, config.securityKey(), idCounter, errors);
        if (promptsListMsg != null) {
            requestCount++;
            prompts = extractPromptDefs(promptsListMsg);
        }

        // 5. resources/read for each discovered resource
        for (String uri : resourceUris) {
            ObjectNode params = MAPPER.createObjectNode();
            params.put("uri", uri);
            HttpMessage msg =
                    sendAndRecord(
                            serverUri,
                            "resources/read",
                            params,
                            config.securityKey(),
                            idCounter,
                            errors);
            if (msg != null) {
                requestCount++;
            }
        }

        // 6. tools/call for each tool with schema-derived placeholder arguments
        for (ToolDef tool : tools) {
            ObjectNode params = MAPPER.createObjectNode();
            params.put("name", tool.name());
            params.set("arguments", buildToolArguments(tool.inputSchema()));
            HttpMessage msg =
                    sendAndRecord(
                            serverUri,
                            "tools/call",
                            params,
                            config.securityKey(),
                            idCounter,
                            errors);
            if (msg != null) {
                requestCount++;
            }
        }

        // 7. prompts/get for each prompt with schema-derived placeholder arguments
        for (PromptDef prompt : prompts) {
            ObjectNode params = MAPPER.createObjectNode();
            params.put("name", prompt.name());
            params.set("arguments", buildPromptArguments(prompt.arguments()));
            HttpMessage msg =
                    sendAndRecord(
                            serverUri,
                            "prompts/get",
                            params,
                            config.securityKey(),
                            idCounter,
                            errors);
            if (msg != null) {
                requestCount++;
            }
        }

        return new ImportResults(requestCount, errors);
    }

    /**
     * Sends a JSON-RPC notification (no {@code id} field) and records it in history. Notifications
     * do not carry a response body, so the recorded message captures the server's acknowledgement
     * (typically HTTP 202) without attempting to parse a JSON-RPC result.
     *
     * @return {@code true} if the notification was sent successfully, {@code false} otherwise
     */
    private boolean sendNotification(URI serverUri, String method, String securityKey) {
        HttpMessage msg = buildNotification(serverUri, method, securityKey);
        if (msg == null) {
            return false;
        }
        try {
            httpSender.sendAndReceive(msg);
        } catch (IOException e) {
            LOGGER.warn("MCP notification failed for method {}: {}", method, e.getMessage());
            return false;
        }
        recordMessage(msg);
        return true;
    }

    private HttpMessage buildNotification(URI serverUri, String method, String securityKey) {
        try {
            ObjectNode body = MAPPER.createObjectNode();
            body.put("jsonrpc", "2.0");
            body.put("method", method);

            HttpMessage msg = new HttpMessage(serverUri);
            msg.getRequestHeader().setMethod(HttpRequestHeader.POST);
            msg.getRequestHeader().setHeader(HttpHeader.CONTENT_TYPE, CONTENT_TYPE);
            if (securityKey != null && !securityKey.isBlank()) {
                msg.getRequestHeader().setHeader("Authorization", securityKey);
            }

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
            AtomicInteger idCounter,
            List<String> errors) {
        HttpMessage msg = buildRequest(serverUri, method, paramsNode, securityKey, idCounter);
        if (msg == null) {
            return null;
        }
        try {
            httpSender.sendAndReceive(msg);
        } catch (IOException e) {
            errors.add("Request failed for " + method + ": " + e.getMessage());
            LOGGER.warn("MCP request failed for method {}: {}", method, e.getMessage());
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
            msg.getRequestHeader().setMethod(HttpRequestHeader.POST);
            msg.getRequestHeader().setHeader(HttpHeader.CONTENT_TYPE, CONTENT_TYPE);
            if (securityKey != null && !securityKey.isBlank()) {
                msg.getRequestHeader().setHeader("Authorization", securityKey);
            }

            String bodyStr = MAPPER.writeValueAsString(body);
            msg.setRequestBody(bodyStr);
            msg.getRequestHeader().setContentLength(msg.getRequestBody().length());
            return msg;
        } catch (Exception e) {
            LOGGER.warn("Failed to build MCP request for method {}: {}", method, e.getMessage());
            return null;
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

    private boolean hasJsonRpcError(HttpMessage msg) {
        try {
            JsonNode response = MAPPER.readTree(msg.getResponseBody().toString());
            return response.has("error");
        } catch (Exception e) {
            return false;
        }
    }

    private String getJsonRpcErrorMessage(HttpMessage msg) {
        try {
            JsonNode response = MAPPER.readTree(msg.getResponseBody().toString());
            JsonNode error = response.get("error");
            if (error != null && error.has("message")) {
                return error.get("message").asText();
            }
        } catch (Exception e) {
            // ignore
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
        try {
            JsonNode toolsNode =
                    MAPPER.readTree(msg.getResponseBody().toString()).path("result").path("tools");
            if (toolsNode.isArray()) {
                for (JsonNode tool : toolsNode) {
                    String name = tool.path("name").asText(null);
                    if (name != null) {
                        tools.add(new ToolDef(name, tool.path("inputSchema")));
                    }
                }
            }
        } catch (Exception e) {
            LOGGER.warn("Failed to parse tools/list response: {}", e.getMessage());
        }
        return tools;
    }

    /** Parses the {@code prompts/list} response into {@link PromptDef} objects. */
    private List<PromptDef> extractPromptDefs(HttpMessage msg) {
        List<PromptDef> prompts = new ArrayList<>();
        try {
            JsonNode promptsNode =
                    MAPPER.readTree(msg.getResponseBody().toString())
                            .path("result")
                            .path("prompts");
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
        } catch (Exception e) {
            LOGGER.warn("Failed to parse prompts/list response: {}", e.getMessage());
        }
        return prompts;
    }

    /**
     * Builds an {@code arguments} object for a {@code tools/call} request by creating a placeholder
     * value for each property in the tool's {@code inputSchema}. String properties receive an RFC
     * 6570 template placeholder (e.g. {@code "{target}"}) so that {@code VariantMcpJsonRpc} exposes
     * them as individual fuzz parameters.
     */
    private ObjectNode buildToolArguments(JsonNode inputSchema) {
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
                                default -> args.put(paramName, "{" + paramName + "}");
                            }
                        });
        return args;
    }

    /**
     * Builds an {@code arguments} object for a {@code prompts/get} request, using an RFC 6570
     * template placeholder for each argument name so that {@code VariantMcpJsonRpc} exposes them as
     * fuzz parameters.
     */
    private ObjectNode buildPromptArguments(List<String> argumentNames) {
        ObjectNode args = MAPPER.createObjectNode();
        for (String name : argumentNames) {
            args.put(name, "{" + name + "}");
        }
        return args;
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
        try {
            JsonNode node = MAPPER.readTree(msg.getResponseBody().toString());
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
        } catch (Exception e) {
            LOGGER.warn("Failed to parse MCP response: {}", e.getMessage());
        }
        return result;
    }
}
