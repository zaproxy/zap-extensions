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

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.DelimiterBasedFrameDecoder;
import io.netty.handler.codec.Delimiters;
import io.netty.handler.codec.string.StringDecoder;
import io.netty.handler.codec.string.StringEncoder;
import io.netty.util.NettyRuntime;
import io.netty.util.concurrent.DefaultThreadFactory;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.network.internal.ChannelAttributes;
import org.zaproxy.addon.network.internal.codec.HttpClientCodec;
import org.zaproxy.addon.network.internal.codec.HttpRequestDecoder;
import org.zaproxy.addon.network.internal.codec.HttpResponseEncoder;
import org.zaproxy.addon.network.internal.server.BaseServer;
import org.zaproxy.addon.network.server.Server;
import org.zaproxy.addon.network.testutils.TestClient;
import org.zaproxy.addon.network.testutils.TextTestClient;

/** Unit test for {@link PassThroughHandler}. */
class PassThroughHandlerUnitTest {

    private static final String CLIENT_CODEC_NAME = "http.client";

    private static final Predicate<HttpRequestHeader> NO_PASSTHROUGH = request -> false;
    private static final Predicate<HttpRequestHeader> PASSTHROUGH_ALL = request -> true;

    private static NioEventLoopGroup eventLoopGroup;
    private static TestClient client;

    private BaseServer proxy;
    private Channel proxyChannel;
    private List<Object> proxyMessagesProcessed;
    private List<Throwable> proxyExceptionsThrown;
    private BaseServer server;
    private List<Object> serverMessagesReceived;

    @BeforeAll
    static void setupAll() throws Exception {
        eventLoopGroup =
                new NioEventLoopGroup(
                        NettyRuntime.availableProcessors(),
                        new DefaultThreadFactory("ZAP-PassThroughHandlerUnitTest"));

        client =
                new TextTestClient(
                        "127.0.0.1",
                        ch -> ch.pipeline().addFirst(CLIENT_CODEC_NAME, new HttpClientCodec()));
    }

    @AfterAll
    static void tearDownAll() throws Exception {
        if (eventLoopGroup != null) {
            eventLoopGroup.shutdownGracefully();
            eventLoopGroup = null;
        }

        if (client != null) {
            client.close();
            client = null;
        }
    }

    @BeforeEach
    void setUp() {
        proxyMessagesProcessed = new ArrayList<>();
        proxyExceptionsThrown = new ArrayList<>();
        serverMessagesReceived = new ArrayList<>();
    }

    @AfterEach
    void cleanUp() throws Exception {
        if (server != null) {
            server.stop();
        }

        if (proxy != null) {
            proxy.stop();
        }

        if (client != null) {
            client.closeChannels();
        }
    }

    private BaseServer createProxy(Predicate<HttpRequestHeader> passThroughCondition) {
        proxy = new BaseServer(eventLoopGroup, ch -> initProxyChannel(ch, passThroughCondition));
        return proxy;
    }

    private void initProxyChannel(
            SocketChannel ch, Predicate<HttpRequestHeader> passThroughCondition) {
        ch.pipeline()
                .addLast(new HttpRequestDecoder())
                .addLast(HttpResponseEncoder.getInstance())
                .addLast(
                        new SimpleChannelInboundHandler<HttpMessage>() {

                            @Override
                            protected void channelRead0(ChannelHandlerContext ctx, HttpMessage msg)
                                    throws Exception {
                                proxyChannel = ctx.channel();
                                ctx.fireChannelRead(msg);
                            }
                        })
                .addLast(new PassThroughHandler(passThroughCondition))
                .addLast(
                        new SimpleChannelInboundHandler<HttpMessage>() {

                            @Override
                            protected void channelRead0(ChannelHandlerContext ctx, HttpMessage msg)
                                    throws Exception {
                                proxyMessagesProcessed.add(msg);
                                msg.getResponseHeader()
                                        .setMessage("HTTP/1.1 200 OK\r\nServer: Proxy");
                                ctx.writeAndFlush(msg);

                                HttpRequestHeader request = msg.getRequestHeader();
                                if (!HttpRequestHeader.CONNECT.equals(request.getMethod())) {
                                    ctx.close();
                                }
                            }

                            @Override
                            public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause)
                                    throws Exception {
                                proxyExceptionsThrown.add(cause);
                                ctx.close();
                            }
                        });
    }

    private int startServer() throws Exception {
        server = new BaseServer(eventLoopGroup, this::initDefaultServerChannel);
        return server.start(Server.ANY_PORT);
    }

    private void initDefaultServerChannel(SocketChannel ch) {
        ch.pipeline()
                .addLast(new DelimiterBasedFrameDecoder(1024, Delimiters.lineDelimiter()))
                .addLast(new StringDecoder(StandardCharsets.UTF_8))
                .addLast(new StringEncoder(StandardCharsets.UTF_8))
                .addLast(
                        new SimpleChannelInboundHandler<String>() {

                            @Override
                            protected void channelRead0(ChannelHandlerContext ctx, String msg)
                                    throws Exception {
                                serverMessagesReceived.add(msg);
                                ctx.writeAndFlush("Received: " + msg + "\n");
                            }
                        });
    }

    @Test
    void shouldThrowExceptionInDecodedHttpMessage() throws Exception {
        // Given
        int proxyPort = createProxy(NO_PASSTHROUGH).start(Server.ANY_PORT);
        // When
        Channel clientChannel = client.connect(proxyPort, null);
        clientChannel.writeAndFlush("MalformedRequest HTTP/1.1\r\n\r\n").sync();
        TextTestClient.waitForResponse(clientChannel);
        // Then
        assertThat(proxyExceptionsThrown, hasSize(1));
        assertThat(proxyMessagesProcessed, hasSize(0));
    }

    @Test
    void shouldNotPassThroughIfDisabled() throws Exception {
        // Given
        int serverPort = startServer();
        int proxyPort = createProxy(NO_PASSTHROUGH).start(Server.ANY_PORT);
        HttpMessage request =
                createHttpRequest("CONNECT 127.0.0.1:" + serverPort + " HTTP/1.1", serverPort);
        // When
        Channel clientChannel = client.connect(proxyPort, null);
        clientChannel.writeAndFlush(request).sync();
        HttpMessage response = (HttpMessage) TextTestClient.waitForResponse(clientChannel);
        // Then
        assertTrue(Boolean.FALSE.equals(proxyChannel.attr(ChannelAttributes.PASS_THROUGH).get()));
        assertThat(proxyMessagesProcessed, hasSize(1));
        assertThat(serverMessagesReceived, hasSize(0));
        assertThat(
                response.getResponseHeader().toString(),
                is(equalTo("HTTP/1.1 200 OK\r\nServer: Proxy\r\n\r\n")));
    }

    @Test
    void shouldNotPassThroughIfNotConnect() throws Exception {
        // Given
        int serverPort = startServer();
        int proxyPort = createProxy(PASSTHROUGH_ALL).start(Server.ANY_PORT);
        HttpMessage request = createHttpRequest("GET / HTTP/1.1", serverPort);
        // When
        Channel clientChannel = client.connect(proxyPort, null);
        clientChannel.writeAndFlush(request).sync();
        HttpMessage response = (HttpMessage) TextTestClient.waitForResponse(clientChannel);
        // Then
        assertTrue(Boolean.FALSE.equals(proxyChannel.attr(ChannelAttributes.PASS_THROUGH).get()));
        assertThat(proxyMessagesProcessed, hasSize(1));
        assertThat(serverMessagesReceived, hasSize(0));
        assertThat(
                response.getResponseHeader().toString(),
                is(equalTo("HTTP/1.1 200 OK\r\nServer: Proxy\r\n\r\n")));
    }

    @Test
    void shouldNotPassThroughIfNotAllowedConnect() throws Exception {
        // Given
        int serverPort = startServer();
        int proxyPort =
                createProxy(connect -> connect.getHostPort() != serverPort).start(Server.ANY_PORT);
        HttpMessage request =
                createHttpRequest("CONNECT 127.0.0.1:" + serverPort + " HTTP/1.1", serverPort);
        // When
        Channel clientChannel = client.connect(proxyPort, null);
        clientChannel.writeAndFlush(request).sync();
        HttpMessage response = (HttpMessage) TextTestClient.waitForResponse(clientChannel);
        // Then
        assertTrue(Boolean.FALSE.equals(proxyChannel.attr(ChannelAttributes.PASS_THROUGH).get()));
        assertThat(proxyMessagesProcessed, hasSize(1));
        assertThat(serverMessagesReceived, hasSize(0));
        assertThat(
                response.getResponseHeader().toString(),
                is(equalTo("HTTP/1.1 200 OK\r\nServer: Proxy\r\n\r\n")));
    }

    @Test
    void shouldPassThroughIfAllowedConnect() throws Exception {
        // Given
        int serverPort = startServer();
        int proxyPort =
                createProxy(connect -> connect.getHostPort() == serverPort).start(Server.ANY_PORT);
        HttpMessage request =
                createHttpRequest("CONNECT 127.0.0.1:" + serverPort + " HTTP/1.1", serverPort);
        // When
        Channel clientChannel = client.connect(proxyPort, null);
        clientChannel.writeAndFlush(request).sync();
        HttpMessage response = (HttpMessage) TextTestClient.waitForResponse(clientChannel);
        assertThat(
                response.getResponseHeader().toString(),
                is(equalTo("HTTP/1.1 200 Connection established\r\n\r\n")));
        clientChannel.pipeline().remove(CLIENT_CODEC_NAME);
        clientChannel.writeAndFlush("Message 1\n").sync();
        String passThroughResponse1 = (String) TextTestClient.waitForResponse(clientChannel);
        clientChannel.writeAndFlush("Message 2\n").sync();
        String passThroughResponse2 = (String) TextTestClient.waitForResponse(clientChannel);
        // Then
        assertTrue(Boolean.TRUE.equals(proxyChannel.attr(ChannelAttributes.PASS_THROUGH).get()));
        assertThat(proxyMessagesProcessed, hasSize(0));
        assertThat(serverMessagesReceived, contains("Message 1", "Message 2"));
        assertThat(passThroughResponse1, is(equalTo("Received: Message 1")));
        assertThat(passThroughResponse2, is(equalTo("Received: Message 2")));
    }

    @Test
    void shouldCloseConnectionIfNotAbleToConnectToTarget() throws Exception {
        // Given
        int invalidPort = 100000;
        int proxyPort = createProxy(PASSTHROUGH_ALL).start(Server.ANY_PORT);
        HttpMessage request =
                createHttpRequest("CONNECT 127.0.0.1:" + invalidPort + " HTTP/1.1", invalidPort);
        // When / Then
        Channel clientChannel = client.connect(proxyPort, null);
        clientChannel.writeAndFlush(request).sync();
        HttpMessage response = (HttpMessage) TextTestClient.waitForResponse(clientChannel);
        assertThat(
                response.getResponseHeader().toString(),
                is(equalTo("HTTP/1.1 200 Connection established\r\n\r\n")));
        assertThrows(
                Exception.class,
                () -> {
                    clientChannel.writeAndFlush("Message 1\n").sync();
                    TextTestClient.waitForResponse(clientChannel);
                    clientChannel.writeAndFlush("Message 2\n").sync();
                    TextTestClient.waitForResponse(clientChannel);
                });
        assertThat(proxyMessagesProcessed, hasSize(0));
        assertThat(serverMessagesReceived, hasSize(0));
    }

    private static HttpMessage createHttpRequest(String requestLine, int port) throws Exception {
        return new HttpMessage(
                new HttpRequestHeader(requestLine + "\r\nHost: 127.0.0.1:" + port + "\r\n\r\n"));
    }
}
