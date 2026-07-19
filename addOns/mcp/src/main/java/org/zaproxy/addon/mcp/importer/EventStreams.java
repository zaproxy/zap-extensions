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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.util.Optional;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;

/**
 * Helpers for accessing the body of an event-stream ({@code Content-Type: text/event-stream})
 * response after {@code HttpSender.sendAndReceive}.
 *
 * <p>The default sender deliberately leaves SSE response bodies empty on the {@link HttpMessage} so
 * the proxy can stream events live. When an add-on initiates the request itself and needs to
 * consume a finite SSE response (e.g. an MCP Streamable HTTP reply that wraps the JSON-RPC payload
 * in a single SSE frame), it can use {@link #getInputStream(HttpMessage)} to read events
 * incrementally or {@link #consumeBody(HttpMessage)} to drain the whole body into the message and
 * release the underlying socket.
 */
final class EventStreams {

    private EventStreams() {}

    /**
     * Returns the event-stream response body as an {@link InputStream}, if one is attached to the
     * given message. Will be present only after a successful {@code sendAndReceive} on a request
     * whose response is {@code text/event-stream}. The caller owns the stream and the underlying
     * socket; both must be closed when reading is finished.
     */
    @SuppressWarnings("deprecation")
    static Optional<InputStream> getInputStream(HttpMessage msg) throws IOException {
        Object userObject = msg.getUserObject();
        if (userObject instanceof org.zaproxy.zap.ZapGetMethod) {
            return Optional.ofNullable(
                    ((org.zaproxy.zap.ZapGetMethod) userObject).getResponseBodyAsStream());
        }
        return Optional.empty();
    }

    /**
     * Returns the underlying {@link Socket} for an event-stream response, if one is attached to the
     * given message. The caller is responsible for closing it.
     */
    @SuppressWarnings("deprecation")
    static Optional<Socket> getSocket(HttpMessage msg) {
        Object userObject = msg.getUserObject();
        if (userObject instanceof org.zaproxy.zap.ZapGetMethod) {
            return Optional.ofNullable(
                    ((org.zaproxy.zap.ZapGetMethod) userObject).getUpgradedConnection());
        }
        return Optional.empty();
    }

    /**
     * Drains the event-stream response body into {@link HttpMessage#setResponseBody(byte[])},
     * updates {@code Content-Length} to match, and closes the underlying socket. Does nothing if
     * the message is not an event-stream response.
     *
     * <p>If the response carries a {@code Content-Length} header, exactly that many bytes are read
     * from the stream so the call does not block waiting for an EOF that never arrives on a
     * keep-alive connection. Otherwise the stream is drained until EOF.
     *
     * @return {@code true} if a body was consumed, {@code false} otherwise.
     */
    static boolean consumeBody(HttpMessage msg) throws IOException {
        Optional<InputStream> stream = getInputStream(msg);
        if (stream.isEmpty()) {
            return false;
        }
        int contentLength = parseContentLength(msg);
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        try (InputStream is = stream.get()) {
            byte[] chunk = new byte[8 * 1024];
            if (contentLength >= 0) {
                int remaining = contentLength;
                while (remaining > 0) {
                    int n = is.read(chunk, 0, Math.min(chunk.length, remaining));
                    if (n < 0) {
                        break;
                    }
                    buf.write(chunk, 0, n);
                    remaining -= n;
                }
            } else {
                int n;
                while ((n = is.read(chunk)) >= 0) {
                    buf.write(chunk, 0, n);
                }
            }
        } finally {
            closeQuietly(getSocket(msg).orElse(null));
        }
        byte[] body = buf.toByteArray();
        msg.setResponseBody(body);
        msg.getResponseHeader().setContentLength(body.length);
        return true;
    }

    private static int parseContentLength(HttpMessage msg) {
        String value = msg.getResponseHeader().getHeader(HttpHeader.CONTENT_LENGTH);
        if (value == null) {
            return -1;
        }
        try {
            int length = Integer.parseInt(value.trim());
            return length >= 0 ? length : -1;
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private static void closeQuietly(Socket socket) {
        if (socket == null) {
            return;
        }
        try {
            socket.close();
        } catch (IOException ignore) {
            // Best effort; nothing to do.
        }
    }
}
