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
package org.zaproxy.addon.network.internal.server.http;

import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.ssl.SslClosedEngineException;
import java.nio.channels.ClosedChannelException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Executor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.network.internal.ChannelAttributes;
import org.zaproxy.addon.network.server.HttpMessageHandler;

/**
 * The main handler of an HTTP server, notifies {@link HttpMessageHandler}s and acts accordingly.
 */
public class MainServerHandler extends SimpleChannelInboundHandler<HttpMessage> {

    private static final String ERROR_WRITE =
            "Failed to write/forward the HTTP response to the client: ";

    protected enum HandlerResult {
        CONTINUE,
        OVERRIDDEN,
        CLOSE,
    }

    private static final Logger LOGGER = LogManager.getLogger(MainServerHandler.class);

    protected final Executor executor;
    protected final List<HttpMessageHandler> pipeline;

    /**
     * Constructs a {@code MainServerHandler} with the given handlers.
     *
     * @param executor the executor to process the HTTP messages.
     * @param handlers the message handlers.
     * @throws NullPointerException if the given list is {@code null}.
     */
    public MainServerHandler(Executor executor, List<HttpMessageHandler> handlers) {
        this.executor = executor;
        this.pipeline = Objects.requireNonNull(handlers);
    }

    @Override
    public void channelRead0(ChannelHandlerContext ctx, HttpMessage msg) throws Exception {
        if (msg.getUserObject() instanceof Exception) {
            throw (Exception) msg.getUserObject();
        }

        executor.execute(
                () -> {
                    ctx.channel().attr(ChannelAttributes.PROCESSING_MESSAGE).set(Boolean.TRUE);
                    try {
                        process(ctx, msg);
                    } finally {
                        ctx.channel().attr(ChannelAttributes.PROCESSING_MESSAGE).set(Boolean.FALSE);
                    }
                });
    }

    private void process(ChannelHandlerContext ctx, HttpMessage msg) {
        DefaultHttpMessageHandlerContext handlerContext =
                new DefaultHttpMessageHandlerContext(
                        ctx.channel(), RecursiveRequestChecker.getInstance());

        if (processMessage(handlerContext, msg) == HandlerResult.CLOSE) {
            close(ctx);
            return;
        }

        writeResponse(ctx, msg);

        if (isCloseRequired(msg)) {
            close(ctx);
            return;
        }

        if (postWriteResponse(ctx, msg)) {
            return;
        }

        if (isConnectionClose(msg)) {
            close(ctx);
        }
    }

    private static boolean isCloseRequired(HttpMessage msg) {
        return Boolean.TRUE.equals(getProperties(msg).get("connection.closed"))
                && msg.getResponseHeader().getHeader(HttpHeader.CONTENT_LENGTH) == null;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> getProperties(HttpMessage message) {
        Object userObject = message.getUserObject();
        if (!(userObject instanceof Map)) {
            return Collections.emptyMap();
        }
        return (Map<String, Object>) userObject;
    }

    protected HandlerResult processMessage(
            DefaultHttpMessageHandlerContext handlerContext, HttpMessage msg) {
        HandlerResult result = notifyMessageHandlers(handlerContext, msg);
        if (result != HandlerResult.CONTINUE) {
            return result;
        }

        handlerContext.handlingResponse(msg);

        result = notifyMessageHandlers(handlerContext, msg);
        if (result != HandlerResult.CONTINUE) {
            return result;
        }

        return HandlerResult.CONTINUE;
    }

    private HandlerResult notifyMessageHandlers(
            DefaultHttpMessageHandlerContext handlerContext, HttpMessage msg) {
        for (HttpMessageHandler handler : pipeline) {
            handlerContext.updateRecursiveState(msg);
            try {
                handler.handleMessage(handlerContext, msg);
            } catch (Throwable e) {
                LOGGER.error("An error occurred while notifying a handler:", e);
            }

            if (handlerContext.isClose()) {
                return HandlerResult.CLOSE;
            }

            if (handlerContext.isOverridden()) {
                return HandlerResult.OVERRIDDEN;
            }
        }

        return HandlerResult.CONTINUE;
    }

    protected boolean postWriteResponse(ChannelHandlerContext ctx, HttpMessage msg) {
        return false;
    }

    private static void writeResponse(ChannelHandlerContext ctx, HttpMessage msg) {
        ctx.writeAndFlush(msg)
                .addListener(
                        e -> {
                            if (!e.isSuccess()) {
                                Throwable cause = e.cause();
                                if (cause instanceof ClosedChannelException
                                        || cause instanceof SslClosedEngineException) {
                                    LOGGER.debug(() -> ERROR_WRITE + "connection closed.");
                                    return;
                                }

                                LOGGER.warn(
                                        () -> {
                                            StringBuilder strBuilder = new StringBuilder(200);
                                            strBuilder.append(ERROR_WRITE);
                                            strBuilder.append(cause.getClass().getName());
                                            if (cause.getMessage() != null) {
                                                strBuilder.append(": ").append(cause.getMessage());
                                            }
                                            return strBuilder;
                                        });
                            }
                        });
    }

    protected static void close(ChannelHandlerContext ctx) {
        ctx.writeAndFlush(Unpooled.EMPTY_BUFFER)
                .addListener(ChannelFutureListener.CLOSE)
                .addListener(
                        e -> {
                            if (!e.isSuccess()) {
                                LOGGER.debug(
                                        "An error occurred while closing the connection.",
                                        e.cause());
                            }
                        });
    }

    private static boolean isConnectionClose(HttpMessage msg) {
        if (HttpRequestHeader.CONNECT.equalsIgnoreCase(msg.getRequestHeader().getMethod())) {
            return false;
        }

        if (Boolean.TRUE.equals(getProperties(msg).get("zap.h2"))) {
            return false;
        }

        if (msg.getResponseHeader().isEmpty()) {
            return true;
        }

        if (msg.getRequestHeader().isConnectionClose()) {
            return true;
        }

        if (msg.getResponseHeader().isConnectionClose()) {
            return true;
        }

        if (msg.getResponseHeader().getContentLength() == -1
                && msg.getResponseBody().length() > 0) {
            return true;
        }

        return false;
    }
}
