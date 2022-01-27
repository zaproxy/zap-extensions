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
package org.zaproxy.addon.network.internal.handlers;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelOption;
import io.netty.channel.ChannelPipelineException;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.timeout.ReadTimeoutException;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.network.internal.ChannelAttributes;

/**
 * Handles HTTTP CONNECT requests to passthrough the data to the server.
 *
 * <p>The whole pipeline is reworked to passthrough the data, otherwise the handler just removes
 * itself.
 */
public class PassthroughHandler extends SimpleChannelInboundHandler<HttpMessage> {

    private static final Logger LOGGER = LogManager.getLogger(PassthroughHandler.class);

    private static final int CONNECT_TIMEOUT_MILLIS = (int) TimeUnit.SECONDS.toMillis(20);
    private static final int READ_TIMEOUT_MINUTES = 2;

    private final Predicate<HttpRequestHeader> passthroughCondition;

    /**
     * Constructs a {@code PassthroughHandler} with the given condition.
     *
     * @param condition the passthrough condition.
     */
    public PassthroughHandler(Predicate<HttpRequestHeader> condition) {
        this.passthroughCondition = Objects.requireNonNull(condition);
    }

    @Override
    public void channelRead0(ChannelHandlerContext ctx, HttpMessage msg) throws Exception {
        if (msg.getUserObject() instanceof Exception) {
            throw (Exception) msg.getUserObject();
        }

        if (!isPassthrough(ctx, msg)) {
            return;
        }

        HttpRequestHeader request = msg.getRequestHeader();
        String host = request.getHostName();
        int port = request.getHostPort();
        LOGGER.debug("Passing through connection to target: {}:{}", host, port);

        ctx.channel().config().setAutoRead(false);
        while (ctx.pipeline().last() != null) {
            ctx.pipeline().remove(ctx.pipeline().last());
        }

        ctx.pipeline()
                .addLast("timeout", new ReadTimeoutHandler(READ_TIMEOUT_MINUTES, TimeUnit.MINUTES));
        ctx.pipeline().addLast("exception", ExceptionHandler.getInstance());
        ctx.pipeline().addAfter("timeout", "passthrough", new ClientSideHandler(host, port));
        ctx.fireChannelReadComplete();
    }

    private boolean isPassthrough(ChannelHandlerContext ctx, HttpMessage msg) {
        boolean passthrough = false;
        try {
            HttpRequestHeader request = msg.getRequestHeader();
            if (!HttpRequestHeader.CONNECT.equals(request.getMethod())) {
                return false;
            }

            passthrough = passthroughCondition.test(request);
            return passthrough;
        } catch (Exception e) {
            LOGGER.error("An error occurred while checking if passthrough request:", e);
            return false;
        } finally {
            ctx.channel().attr(ChannelAttributes.PASSTHROUGH).set(passthrough);
            ctx.fireChannelRead(msg);
            ctx.pipeline().remove(this);
        }
    }

    private static class ClientSideHandler extends ChannelInboundHandlerAdapter {

        private static final Logger LOGGER = LogManager.getLogger(ClientSideHandler.class);

        private final String host;
        private final int port;

        private Channel outboundChannel;

        public ClientSideHandler(String host, int port) {
            this.host = host;
            this.port = port;
        }

        @Override
        public void handlerAdded(ChannelHandlerContext ctx) throws Exception {
            Channel inboundChannel = ctx.channel();
            ChannelFuture f =
                    new Bootstrap()
                            .group(inboundChannel.eventLoop())
                            .channel(ctx.channel().getClass())
                            .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, CONNECT_TIMEOUT_MILLIS)
                            .handler(new ServerSideHandler(inboundChannel))
                            .option(ChannelOption.AUTO_READ, false)
                            .connect(host, port);
            outboundChannel = f.channel();
            outboundChannel
                    .pipeline()
                    .addFirst(new ReadTimeoutHandler(READ_TIMEOUT_MINUTES, TimeUnit.MINUTES));
            f.addListener(
                    future -> {
                        if (future.isSuccess()) {
                            LOGGER.debug("Connected to: {}:{}", host, port);
                            inboundChannel.read();
                        } else {
                            LOGGER.warn(
                                    "Failed to connect to target: {}:{}",
                                    host,
                                    port,
                                    future.cause());
                            inboundChannel.close();
                        }
                    });
        }

        @Override
        public void channelRead(final ChannelHandlerContext ctx, Object msg) {
            if (outboundChannel.isActive()) {
                outboundChannel
                        .writeAndFlush(msg)
                        .addListener(
                                (ChannelFuture future) -> {
                                    if (future.isSuccess()) {
                                        ctx.channel().read();
                                    } else {
                                        future.channel().close();
                                    }
                                });
            }
        }

        @Override
        public void channelInactive(ChannelHandlerContext ctx) {
            LOGGER.debug("Client side is inactive, closing.");

            if (outboundChannel != null) {
                closeOnFlush(outboundChannel);
            }
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            if (cause instanceof ReadTimeoutException) {
                LOGGER.debug("Timed out while reading from client.");
            } else {
                LOGGER.debug("Exception while handling client side.", cause);
            }

            closeOnFlush(ctx.channel());
        }
    }

    private static class ServerSideHandler extends ChannelInboundHandlerAdapter {

        private static final Logger LOGGER = LogManager.getLogger(ServerSideHandler.class);

        private final Channel inboundChannel;

        public ServerSideHandler(Channel inboundChannel) {
            this.inboundChannel = inboundChannel;
        }

        @Override
        public void channelActive(ChannelHandlerContext ctx) {
            ctx.read();
        }

        @Override
        public void channelRead(final ChannelHandlerContext ctx, Object msg) {
            inboundChannel
                    .writeAndFlush(msg)
                    .addListener(
                            (ChannelFuture future) -> {
                                if (future.isSuccess()) {
                                    ctx.channel().read();
                                } else {
                                    future.channel().close();
                                }
                            });
        }

        @Override
        public void channelInactive(ChannelHandlerContext ctx) {
            LOGGER.debug("Server side is inactive, closing.");

            closeOnFlush(inboundChannel);
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            if (cause instanceof ReadTimeoutException) {
                LOGGER.debug("Timed out while reading from server.");
            } else {
                LOGGER.debug("Exception while handling server side.", cause);
            }

            closeOnFlush(ctx.channel());
        }
    }

    private static void closeOnFlush(Channel ch) {
        if (ch.isActive()) {
            ch.writeAndFlush(Unpooled.EMPTY_BUFFER).addListener(ChannelFutureListener.CLOSE);
        }
    }

    private static class ExceptionHandler extends ChannelInboundHandlerAdapter {

        private static final ExceptionHandler INSTANCE = new ExceptionHandler();

        public static ExceptionHandler getInstance() {
            return INSTANCE;
        }

        @Override
        public boolean isSharable() {
            return true;
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
            if (cause instanceof ChannelPipelineException) {
                LOGGER.warn(
                        "Failed while connecting to passthrough to target: {}",
                        cause.getCause().getMessage());
                ctx.close();
                return;
            }

            ServerExceptionHandler.getInstance().exceptionCaught(ctx, cause);
        }
    }
}
