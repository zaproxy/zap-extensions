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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpHeader;
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
            String addOnVersion) {
        this.param = param;
        this.requestHandler = new McpRequestHandler(toolRegistry, resourceRegistry, addOnVersion);
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

            String requiredKey = param.getRequiredSecurityKey();
            if (requiredKey != null) {
                String authHeader =
                        msg.getRequestHeader().getHeader(HttpRequestHeader.AUTHORIZATION);
                String providedKey = authHeader != null ? authHeader.trim() : "";
                if (!requiredKey.equals(providedKey)) {
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
            if (requestBody == null || requestBody.isBlank()) {
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
        byte[] bodyBytes = body.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        String header =
                "HTTP/1.1 "
                        + HttpStatusCode.OK
                        + "\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\nContent-Length: "
                        + bodyBytes.length
                        + getCorsHeaders();
        msg.setResponseHeader(header);
        msg.setResponseBody(body);
    }

    private void setOptionsResponse(HttpMessage msg) throws HttpMalformedHeaderException {
        String header =
                "HTTP/1.1 "
                        + HttpStatusCode.OK
                        + "\r\nContent-Length: 0\r\nConnection: close"
                        + "\r\nAccess-Control-Allow-Origin: *"
                        + "\r\nAccess-Control-Allow-Methods: POST, GET, OPTIONS"
                        + "\r\nAccess-Control-Allow-Headers: Content-Type, Accept, Authorization, MCP-Protocol-Version, MCP-Session-Id";
        msg.setResponseHeader(header);
        msg.setResponseBody("");
    }

    private static String getCorsHeaders() {
        return "\r\nAccess-Control-Allow-Origin: *"
                + "\r\nAccess-Control-Allow-Methods: POST, GET, OPTIONS"
                + "\r\nAccess-Control-Allow-Headers: Content-Type, Accept, Authorization, MCP-Protocol-Version, MCP-Session-Id";
    }

    private void setJsonResponse(HttpMessage msg, int statusCode, String body)
            throws HttpMalformedHeaderException {
        byte[] bodyBytes = body.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        String header =
                "HTTP/1.1 "
                        + statusCode
                        + "\r\nContent-Type: application/json; charset=UTF-8\r\nContent-Length: "
                        + bodyBytes.length
                        + "\r\nConnection: close"
                        + getCorsHeaders();
        msg.setResponseHeader(header);
        msg.setResponseBody(new String(bodyBytes, java.nio.charset.StandardCharsets.UTF_8));
        if ("HTTP/2".equalsIgnoreCase(msg.getRequestHeader().getVersion())) {
            msg.getResponseHeader().setHeader(HttpHeader.CONNECTION, null);
        }
    }

    private void setAcceptedResponse(HttpMessage msg) throws HttpMalformedHeaderException {
        String header =
                "HTTP/1.1 "
                        + HttpStatusCode.ACCEPTED
                        + "\r\nContent-Length: 0\r\nConnection: close"
                        + getCorsHeaders();
        msg.setResponseHeader(header);
        msg.setResponseBody("");
        if ("HTTP/2".equalsIgnoreCase(msg.getRequestHeader().getVersion())) {
            msg.getResponseHeader().setHeader(HttpHeader.CONNECTION, null);
        }
    }

    private void setErrorResponse(HttpMessage msg, int statusCode, String message)
            throws HttpMalformedHeaderException {
        String body =
                "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":"
                        + McpRequestHandler.ERROR_INVALID_REQUEST
                        + ",\"message\":\""
                        + escapeJson(message)
                        + "\"}}";
        setJsonResponse(msg, statusCode, body);
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
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
