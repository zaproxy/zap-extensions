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

import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.addon.network.server.HttpMessageHandler;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

/**
 * HTTP message handler for the MCP server. Handles incoming HTTP requests and dispatches JSON-RPC
 * messages to MCP endpoints.
 */
class McpHttpMessageHandler implements HttpMessageHandler {

    private static final Logger LOGGER = LogManager.getLogger(McpHttpMessageHandler.class);

    private final McpParam param;
    private final McpRequestHandler requestHandler;

    McpHttpMessageHandler(
            McpParam param,
            McpToolRegistry toolRegistry,
            McpResourceRegistry resourceRegistry,
            McpPromptRegistry promptRegistry,
            String addOnVersion) {
        this.param = param;
        this.requestHandler =
                new McpRequestHandler(toolRegistry, resourceRegistry, promptRegistry, addOnVersion);
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
        if (!ctx.isFromClient()) {
            return;
        }
        ctx.overridden();

        try {
            String method = msg.getRequestHeader().getMethod();

            LOGGER.debug(
                    "MCP request: {} from {}", method, msg.getRequestHeader().getSenderAddress());

            if (HttpRequestHeader.OPTIONS.equalsIgnoreCase(method)) {
                setOptionsResponse(msg);
                recordInHistoryIfEnabled(msg);
                return;
            }

            if (param.isSecureOnly() && !msg.getRequestHeader().isSecure()) {
                setErrorResponse(msg, HttpStatusCode.FORBIDDEN, "HTTPS required");
                recordInHistoryIfEnabled(msg);
                return;
            }

            String requiredKey = param.getRequiredSecurityKey();
            if (requiredKey != null) {
                String authHeader =
                        msg.getRequestHeader().getHeader(HttpRequestHeader.AUTHORIZATION);
                String providedKey = authHeader != null ? authHeader.trim() : "";
                if (!MessageDigest.isEqual(
                        requiredKey.getBytes(StandardCharsets.UTF_8),
                        providedKey.getBytes(StandardCharsets.UTF_8))) {
                    setErrorResponse(
                            msg, HttpStatusCode.UNAUTHORIZED, "Invalid or missing security key");
                    recordInHistoryIfEnabled(msg);
                    return;
                }
            }

            if (HttpRequestHeader.GET.equalsIgnoreCase(method)) {
                setSseEndpointResponse(msg);
                return;
            }

            if (!HttpRequestHeader.POST.equalsIgnoreCase(method)) {
                setErrorResponse(msg, HttpStatusCode.METHOD_NOT_ALLOWED, "Method not allowed");
                recordInHistoryIfEnabled(msg);
                return;
            }

            String requestBody = msg.getRequestBody().toString();
            if (requestBody.isBlank()) {
                setErrorResponse(msg, HttpStatusCode.BAD_REQUEST, "Request body required");
                recordInHistoryIfEnabled(msg);
                return;
            }
            LOGGER.debug(
                    "MCP request details : {} {} from {}",
                    method,
                    requestBody,
                    msg.getRequestHeader().getSenderAddress());

            String responseBody = requestHandler.handleRequest(requestBody);
            LOGGER.debug("MCP response details: {}", responseBody);

            if (responseBody == null) {
                setAcceptedResponse(msg);
            } else {
                setJsonResponse(msg, HttpStatusCode.OK, responseBody);
            }
            recordInHistoryIfEnabled(msg);
        } catch (HttpMalformedHeaderException e) {
            LOGGER.error("Failed to set MCP response header", e);
        }
    }

    private void setSseEndpointResponse(HttpMessage msg) throws HttpMalformedHeaderException {
        String body = ": connected\r\n\r\n";
        String header =
                """
                HTTP/1.1 200\r
                Content-Type: text/event-stream\r
                Cache-Control: no-cache\r
                Connection: keep-alive\r
                """
                        + getCorsHeaders();
        msg.setResponseHeader(header);
        msg.setResponseBody(body);
        msg.getResponseHeader().setContentLength(msg.getResponseBody().length());
    }

    private void setOptionsResponse(HttpMessage msg) throws HttpMalformedHeaderException {
        String header =
                """
                HTTP/1.1 200\r
                Content-Length: 0\r
                Access-Control-Allow-Origin: *\r
                Access-Control-Allow-Methods: POST, GET, OPTIONS\r
                Access-Control-Allow-Headers: Content-Type, Accept, Authorization, MCP-Protocol-Version, MCP-Session-Id\r
                """;
        msg.setResponseHeader(header);
        msg.setResponseBody("");
    }

    private static String getCorsHeaders() {
        return """
                \r
                Access-Control-Allow-Origin: *\r
                Access-Control-Allow-Methods: POST, GET, OPTIONS\r
                Access-Control-Allow-Headers: Content-Type, Accept, Authorization, MCP-Protocol-Version, MCP-Session-Id\r
                """;
    }

    private void setJsonResponse(HttpMessage msg, int statusCode, String body)
            throws HttpMalformedHeaderException {
        String header =
                """
                HTTP/1.1 %d\r
                Content-Type: application/json; charset=UTF-8\r
                """
                                .formatted(statusCode)
                        + getCorsHeaders();
        msg.setResponseHeader(header);
        msg.setResponseBody(body);
        msg.getResponseHeader().setContentLength(body.length());
    }

    private void setAcceptedResponse(HttpMessage msg) throws HttpMalformedHeaderException {
        String header =
                """
                HTTP/1.1 202\r
                Content-Length: 0\r
                """
                        + getCorsHeaders();
        msg.setResponseHeader(header);
        msg.setResponseBody("");
    }

    private void setErrorResponse(HttpMessage msg, int statusCode, String message)
            throws HttpMalformedHeaderException {
        int jsonRpcCode = httpStatusToJsonRpcCode(statusCode);
        ObjectNode error = McpRequestHandler.OBJECT_MAPPER.createObjectNode();
        error.put("code", jsonRpcCode);
        error.put("message", message);
        ObjectNode body = McpRequestHandler.OBJECT_MAPPER.createObjectNode();
        body.put("jsonrpc", "2.0");
        body.set("error", error);
        setJsonResponse(msg, statusCode, body.toString());
    }

    private static int httpStatusToJsonRpcCode(int httpStatus) {
        return switch (httpStatus) {
            case HttpStatusCode.BAD_REQUEST -> McpRequestHandler.ERROR_INVALID_REQUEST;
            default -> McpRequestHandler.ERROR_SERVER;
        };
    }

    private void recordInHistoryIfEnabled(HttpMessage msg) {
        if (!param.isRecordInHistory()) {
            return;
        }
        ExtensionHistory extHistory =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionHistory.class);
        if (extHistory != null && !msg.getResponseHeader().isEmpty()) {
            extHistory.addHistory(msg, HistoryReference.TYPE_PROXIED);
        }
    }
}
