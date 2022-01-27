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
package org.zaproxy.addon.network.testutils;

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler.Sharable;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.DelimiterBasedFrameDecoder;
import io.netty.handler.codec.Delimiters;
import io.netty.handler.codec.string.StringDecoder;
import io.netty.handler.codec.string.StringEncoder;
import io.netty.util.AttributeKey;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** A client that allows to send and receive text messages, to help with the tests. */
public class TextTestClient extends TestClient {

    private static final AttributeKey<CompletableFuture<Object>> RESPONSE_ATTRIBUTE =
            AttributeKey.newInstance("zap.client.response");

    /**
     * Constructs a {@code TextTestClient} with the given address.
     *
     * @param address the address to connect to.
     */
    public TextTestClient(String address) {
        this(address, null);
    }

    /**
     * Constructs a {@code TextTestClient} with the given address and channel decorator.
     *
     * @param address the address to connect to.
     * @param channelDecorator the channel decorator, called after the channel is initialised.
     */
    public TextTestClient(String address, Consumer<SocketChannel> channelDecorator) {
        super(address, ch -> initChannel(ch, channelDecorator));
    }

    private static void initChannel(
            SocketChannel channel, Consumer<SocketChannel> channelDecorator) {
        channel.attr(RESPONSE_ATTRIBUTE).set(new CompletableFuture<>());
        channel.pipeline()
                .addLast(new DelimiterBasedFrameDecoder(1024, Delimiters.lineDelimiter()))
                .addLast(new StringDecoder(StandardCharsets.UTF_8))
                .addLast(new StringEncoder(StandardCharsets.UTF_8))
                .addLast(new ResponseHandler())
                .addLast(ServerExceptionHandler.getInstance());

        if (channelDecorator != null) {
            channelDecorator.accept(channel);
        }
    }

    @Override
    public <T> Channel connect(int port, T msg) throws Exception {
        Channel channel = super.connect(port, msg != null ? msg + "\n" : msg);
        if (msg != null) {
            waitForResponse(channel);
        }
        return channel;
    }

    /**
     * Waits for a response in the given channel.
     *
     * @param channel the channel where it's expected a response.
     * @return the response.
     * @throws Exception if an error occurred while waiting for the response.
     */
    public static Object waitForResponse(Channel channel) throws Exception {
        Object response = getCompletableFuture(channel).get(5, TimeUnit.SECONDS);
        channel.attr(RESPONSE_ATTRIBUTE).set(new CompletableFuture<>());
        return response;
    }

    private static CompletableFuture<Object> getCompletableFuture(Channel channel) {
        return channel.attr(RESPONSE_ATTRIBUTE).get();
    }

    private static class ResponseHandler extends SimpleChannelInboundHandler<Object> {

        private static CompletableFuture<Object> getCompletableFuture(ChannelHandlerContext ctx) {
            return TextTestClient.getCompletableFuture(ctx.channel());
        }

        @Override
        public void channelInactive(ChannelHandlerContext ctx) throws Exception {
            super.channelInactive(ctx);
            getCompletableFuture(ctx).complete(null);
            ctx.close();
        }

        @Override
        public void channelRead0(ChannelHandlerContext ctx, Object msg) throws Exception {
            getCompletableFuture(ctx).complete(msg);
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            getCompletableFuture(ctx).completeExceptionally(cause);
            ctx.close();
        }
    }

    @Sharable
    private static class ServerExceptionHandler extends ChannelInboundHandlerAdapter {

        private static final Logger LOGGER = LogManager.getLogger(ServerExceptionHandler.class);

        private static final ServerExceptionHandler INSTANCE = new ServerExceptionHandler();

        static ServerExceptionHandler getInstance() {
            return INSTANCE;
        }

        @Override
        public boolean isSharable() {
            return true;
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
            LOGGER.error(cause);
            ctx.close();
        }
    }
}
