/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.network.server;

import java.io.IOException;
import java.io.OutputStream;
import org.parosproxy.paros.network.HttpMessage;

/**
 * The context for message handlers.
 *
 * <p>Allows to query the state and control how the message is forwarded.
 *
 * @since 0.1.0
 * @see HttpMessageHandler
 */
public interface HttpMessageHandlerContext {

    /**
     * Tells whether or not the message is for the server itself.
     *
     * @return {@code true} if the message is for the server itself, {@code false} otherwise.
     */
    boolean isRecursive();

    /**
     * Tells whether or not the message is excluded.
     *
     * <p>Excluded messages are not meant to be changed in any way while being forwarded.
     *
     * @return {@code true} if the message is excluded, {@code false} otherwise.
     */
    boolean isExcluded();

    /**
     * Tells whether or not the message is from the client.
     *
     * @return {@code true} if the message is from the client, {@code false} otherwise.
     */
    boolean isFromClient();

    /**
     * Indicates that the message contents were overridden and should be forwarded as is.
     *
     * <p>No other handlers will be notified.
     */
    void overridden();

    /**
     * Indicates that the connection should be closed without forwarding the message.
     *
     * <p>No other handlers will be notified.
     */
    void close();

    /**
     * Starts streaming the response of the given message, which is sent to the client as the data
     * is written to the returned stream, for responses that trickle in or are open for a long time.
     *
     * <p>The response header is sent straight away, as it is, and the body of the message is not
     * sent, its response body is emptied. The data written to the stream is sent as it is, with no
     * changes.
     *
     * <p>The responsibility of the connection state is with the caller, for example, the framing of
     * the response (see {@link ChunkedOutputStream}) and when to close the connection. Closing the
     * stream closes the connection, so the context is not needed to do so.
     *
     * <p>The message is not forwarded after the handler returns, and no other handlers are
     * notified, as if {@link #overridden()} was called. Nothing is passed to the listeners of
     * persistent connections (for example, WebSocket or server-sent events) either.
     *
     * <p>The calls to the stream block until the data was written, and fail if the connection was
     * closed. The handler is blocked for as long as the response is streamed, which is not a
     * problem for handlers called from the threads of the server, but must not be called from the
     * event loop of the connection.
     *
     * @param msg the message with the response header to send.
     * @return the stream to write the body to.
     * @throws IOException if an error occurred while sending the response header.
     * @throws IllegalStateException if the response was already started.
     * @since 0.34.0
     */
    OutputStream streamingResponse(HttpMessage msg) throws IOException;
}
