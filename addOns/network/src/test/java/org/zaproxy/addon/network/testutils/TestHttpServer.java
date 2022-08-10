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

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.FixedLengthFrameDecoder;
import io.netty.util.concurrent.EventExecutorGroup;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.security.SslCertificateService;
import org.zaproxy.addon.network.internal.server.http.HttpServer;
import org.zaproxy.addon.network.internal.server.http.MainServerHandler;
import org.zaproxy.addon.network.server.HttpMessageHandler;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

/** A HTTP server that allows to receive and send text messages, to help with the tests. */
public class TestHttpServer extends HttpServer {

    private static final SslCertificateService SSL_CERTIFICATE_SERVICE =
            TestSslCertificateService.createInstance();

    private final List<HttpMessage> receivedMessages;
    private HttpMessageHandler handler;
    private Integer fixedLengthMessage;
    private RawHandler rawHandler;

    /**
     * Constructs a {@code TestHttpServer} with the given properties.
     *
     * @param group the event loop group.
     * @param mainHandlerExecutor the event executor for the main handler.
     */
    public TestHttpServer(NioEventLoopGroup group, EventExecutorGroup mainHandlerExecutor) {
        super(group, mainHandlerExecutor, SSL_CERTIFICATE_SERVICE);

        receivedMessages = Collections.synchronizedList(new ArrayList<>());
        setMainServerHandler(() -> new MainServerHandler(Collections.singletonList(this::handle)));
    }

    @Override
    protected void initChannel(SocketChannel ch) {
        super.initChannel(ch);

        if (fixedLengthMessage != null) {
            ch.pipeline()
                    .replace(
                            "http.decoder",
                            "http.decoder",
                            new FixedLengthFrameDecoder(fixedLengthMessage) {
                                @Override
                                protected Object decode(ChannelHandlerContext ctx, ByteBuf in)
                                        throws Exception {
                                    ByteBuf decoded = (ByteBuf) super.decode(ctx, in);
                                    if (decoded == null) {
                                        return null;
                                    }

                                    String data = decoded.toString(StandardCharsets.UTF_8);
                                    int idx = data.indexOf("\r\n\r\n");
                                    HttpMessage message =
                                            new HttpMessage(
                                                    new HttpRequestHeader(data.substring(0, idx)));
                                    idx += 4;
                                    if (idx < data.length()) {
                                        message.setRequestBody(data.substring(idx));
                                    }
                                    return message;
                                }
                            });
        }

        if (rawHandler != null) {
            ch.pipeline()
                    .addAfter(
                            "http.recursive",
                            "raw.handler",
                            new SimpleChannelInboundHandler<HttpMessage>() {

                                @Override
                                protected void channelRead0(
                                        ChannelHandlerContext ctx, HttpMessage msg)
                                        throws Exception {
                                    rawHandler.handleMessage(ctx, msg);
                                }
                            });
        }
    }

    /**
     * Sets the size of the message that will be received.
     *
     * <p>Allows to read malformed HTTP requests.
     *
     * @param fixedLengthMessage the length of the message.
     */
    public void setFixedLengthMessage(Integer fixedLengthMessage) {
        this.fixedLengthMessage = fixedLengthMessage;
    }

    private void handle(HttpMessageHandlerContext ctx, HttpMessage msg) {
        if (ctx.isFromClient()) {
            return;
        }

        receivedMessages.add(msg);

        if (handler != null) {
            handler.handleMessage(ctx, msg);
        }
    }

    /** Gets the messages received by the server. @return the messages received by the server. */
    public List<HttpMessage> getReceivedMessages() {
        return receivedMessages;
    }

    /**
     * Sets the handler to provide custom responses.
     *
     * @param handler the handler.
     */
    public void setHttpMessageHandler(TestHttpMessageHandler handler) {
        this.handler = new TestHttpMessageHandlerImpl(handler);
    }

    /**
     * Sets the handler to provide custom raw responses.
     *
     * @param handler the handler.
     */
    public void setRawHandler(RawHandler handler) {
        this.rawHandler = handler;
    }

    /** The handler of received messages. */
    public interface TestHttpMessageHandler {

        /**
         * Called when a message is received.
         *
         * @param ctx the context.
         * @param msg the message.
         * @throws Exception if an error occurred.
         */
        void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) throws Exception;
    }

    /** The handler for raw responses. */
    public interface RawHandler {

        /**
         * Called when a message is received.
         *
         * @param ctx the channel handler context.
         * @param msg the message.
         * @throws Exception if an error occurred.
         */
        void handleMessage(ChannelHandlerContext ctx, HttpMessage msg) throws Exception;
    }

    private static class TestHttpMessageHandlerImpl implements HttpMessageHandler {

        private final TestHttpMessageHandler delegatee;

        private TestHttpMessageHandlerImpl(TestHttpMessageHandler delegatee) {
            this.delegatee = delegatee;
        }

        @Override
        public final void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
            try {
                delegatee.handleMessage(ctx, msg);
            } catch (Throwable e) {
                throw new RuntimeException("Test error:", e);
            }
        }
    }
}
