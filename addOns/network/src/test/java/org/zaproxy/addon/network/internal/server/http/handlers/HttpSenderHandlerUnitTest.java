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
package org.zaproxy.addon.network.internal.server.http.handlers;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyInt;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.util.NettyRuntime;
import io.netty.util.concurrent.DefaultEventExecutorGroup;
import io.netty.util.concurrent.DefaultThreadFactory;
import io.netty.util.concurrent.EventExecutorGroup;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.ConnectionParam;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.security.SslCertificateService;
import org.zaproxy.addon.network.internal.server.http.HttpServer;
import org.zaproxy.addon.network.internal.server.http.MainServerHandler;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;
import org.zaproxy.addon.network.server.Server;
import org.zaproxy.addon.network.testutils.TestSslCertificateService;
import org.zaproxy.zap.network.HttpSenderListener;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.I18N;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link HttpSenderHandler}. */
class HttpSenderHandlerUnitTest extends TestUtils {

    private static NioEventLoopGroup eventLoopGroup;
    private static EventExecutorGroup eventExecutorGroup;
    private static SslCertificateService sslCertificateService;

    private ServerAction serverAction;
    private List<HttpMessage> messagesReceived;
    private HttpServer server;
    private int serverPort;
    private HttpMessageHandlerContext ctx;
    private ConnectionParam connectionParam;
    private int initiator = 6;
    private HttpSenderHandler handler;

    @BeforeAll
    static void setupAll() throws Exception {
        sslCertificateService = TestSslCertificateService.createInstance();
        eventLoopGroup =
                new NioEventLoopGroup(
                        NettyRuntime.availableProcessors(),
                        new DefaultThreadFactory("ZAP-IO-HttpSenderHandlerUnitTest"));
        eventExecutorGroup =
                new DefaultEventExecutorGroup(
                        NettyRuntime.availableProcessors(),
                        new DefaultThreadFactory(
                                "ZAP-EventExecutor-HttpSenderHandlerUnitTest",
                                Thread.MAX_PRIORITY));
    }

    @AfterAll
    static void tearDownAll() throws Exception {
        if (eventLoopGroup != null) {
            eventLoopGroup.shutdownGracefully().sync();
            eventLoopGroup = null;
        }
        if (eventExecutorGroup != null) {
            eventExecutorGroup.shutdownGracefully().sync();
            eventExecutorGroup = null;
        }
    }

    @BeforeEach
    void setUp() throws IOException {
        Constant.messages = new I18N(Locale.ENGLISH);

        serverAction =
                (ctx, msg) -> {
                    msg.getResponseHeader().setMessage("HTTP/1.1 200 OK");
                    ctx.writeAndFlush(msg).addListener(ChannelFutureListener.CLOSE);
                };
        messagesReceived = new ArrayList<>();

        server =
                new HttpServer(
                        eventLoopGroup,
                        eventExecutorGroup,
                        sslCertificateService,
                        () ->
                                new MainServerHandler(Collections.emptyList()) {
                                    @Override
                                    public void channelRead0(
                                            ChannelHandlerContext ctx, HttpMessage msg)
                                            throws Exception {
                                        messagesReceived.add(msg);
                                        serverAction.accept(ctx, msg);
                                    };
                                });
        serverPort = server.start(Server.ANY_PORT);

        ctx = mock(HttpMessageHandlerContext.class);
        connectionParam = new ConnectionParam();
        connectionParam.load(new ZapXmlConfiguration());
        handler = new HttpSenderHandler(connectionParam, initiator);
    }

    @AfterEach
    void teardown() throws IOException {
        server.stop();
    }

    @Test
    void shouldThrowIfConnectionParamIsNull() {
        // Given
        ConnectionParam connectionParam = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> new HttpSenderHandler(connectionParam, 1));
    }

    @Test
    void shouldNotHandleResponse() {
        // Given
        given(ctx.isFromClient()).willReturn(false);
        HttpMessage message = createServerRequest("GET / HTTP/1.1");
        // When
        handler.handleMessage(ctx, message);
        // Then
        assertThat(messagesReceived, hasSize(0));
    }

    @Test
    void shouldSendAndReceiveMessage() {
        // Given
        given(ctx.isFromClient()).willReturn(true);
        HttpMessage message = createServerRequest("GET / HTTP/1.1");
        // When
        handler.handleMessage(ctx, message);
        // Then
        assertThat(messagesReceived, hasSize(1));
        assertThat(message.getResponseHeader().toString(), startsWith("HTTP/1.1 200 OK\r\n\r\n"));
        assertThat(message.getResponseBody().toString(), is(equalTo("")));
    }

    @Test
    void shouldSendMessageWithProvidedInitiator() {
        HttpSenderListener listener = mock(HttpSenderListener.class);
        try {
            // Given
            given(ctx.isFromClient()).willReturn(true);
            HttpSender.addListener(listener);
            HttpMessage message = createServerRequest("GET / HTTP/1.1");
            // When
            handler.handleMessage(ctx, message);
            // Then
            verify(listener).onHttpRequestSend(eq(message), eq(initiator), any());
            verify(listener).onHttpResponseReceive(eq(message), eq(initiator), any());
        } finally {
            HttpSender.removeListener(listener);
        }
    }

    @Test
    void shouldSendMessageWithoutNotifyingListenersIfExcluded() {
        HttpSenderListener listener = mock(HttpSenderListener.class);
        try {
            // Given
            given(ctx.isFromClient()).willReturn(true);
            given(ctx.isExcluded()).willReturn(true);
            HttpSender.addListener(listener);
            HttpMessage message = createServerRequest("GET / HTTP/1.1");
            // When
            handler.handleMessage(ctx, message);
            // Then
            verify(listener, times(0)).onHttpRequestSend(any(), anyInt(), any());
            verify(listener, times(0)).onHttpResponseReceive(any(), anyInt(), any());
            verify(ctx).overridden();
        } finally {
            HttpSender.removeListener(listener);
        }
    }

    @Test
    void shouldReturnGatewayTimeoutForTimeout() {
        // Given
        given(ctx.isFromClient()).willReturn(true);
        HttpMessage message = createServerRequest("GET / HTTP/1.1");
        int timeout = 1;
        connectionParam.setTimeoutInSecs(timeout);
        serverAction = (ctx, msg) -> Thread.sleep(timeout * 2);
        // When
        handler.handleMessage(ctx, message);
        // Then
        assertThat(messagesReceived, hasSize(1));
        verify(ctx, times(0)).overridden();
        verify(ctx, times(0)).close();
        assertThat(
                message.getResponseHeader().toString(), startsWith("HTTP/1.1 504 Gateway Timeout"));
        assertThat(
                message.getResponseBody().toString(),
                is(equalTo("!network.httpsender.error.readtimeout!")));
    }

    @Test
    void shouldNotIncludeErrorBodyIfHeadRequest() {
        // Given
        given(ctx.isFromClient()).willReturn(true);
        HttpMessage message = createServerRequest("HEAD / HTTP/1.1");
        int timeout = 1;
        connectionParam.setTimeoutInSecs(timeout);
        serverAction = (ctx, msg) -> Thread.sleep(timeout * 2);
        // When
        handler.handleMessage(ctx, message);
        // Then
        assertThat(messagesReceived, hasSize(1));
        verify(ctx, times(0)).overridden();
        verify(ctx, times(0)).close();
        assertThat(
                message.getResponseHeader().toString(), startsWith("HTTP/1.1 504 Gateway Timeout"));
        assertThat(message.getResponseBody().toString(), is(equalTo("")));
    }

    @Test
    void shouldReturnBadGatewayForIoException() {
        // Given
        given(ctx.isFromClient()).willReturn(true);
        HttpMessage message = createServerRequest("GET / HTTP/1.1");
        serverAction = (ctx, msg) -> ctx.close();
        // When
        handler.handleMessage(ctx, message);
        // Then
        assertThat(messagesReceived, hasSize(greaterThan(1)));
        verify(ctx, times(0)).overridden();
        verify(ctx, times(0)).close();
        assertThat(message.getResponseHeader().toString(), startsWith("HTTP/1.1 502 Bad Gateway"));
        assertThat(
                message.getResponseBody().toString(),
                allOf(startsWith("ZAP Error ["), containsString("Stack Trace:")));
    }

    @Test
    void shouldCloseWithoutSettingResponseOnHttpProtocolError() {
        // Given
        given(ctx.isFromClient()).willReturn(true);
        HttpMessage message = createServerRequest("GET / HTTP/1.1");
        serverAction =
                (ctx, msg) ->
                        ctx.writeAndFlush(
                                        Unpooled.copiedBuffer(
                                                "Invalid HTTP Response\r\n\r\n",
                                                StandardCharsets.US_ASCII))
                                .addListener(ChannelFutureListener.CLOSE);
        // When
        handler.handleMessage(ctx, message);
        // Then
        assertThat(messagesReceived, hasSize(1));
        verify(ctx).close();
        assertThat(message.getResponseHeader().toString(), startsWith("HTTP/1.0 0\r\n\r\n"));
        assertThat(message.getResponseBody().toString(), is(equalTo("")));
    }

    private HttpMessage createServerRequest(String request) {
        try {
            return new HttpMessage(
                    new HttpRequestHeader(
                            request + "\r\nHost: 127.0.0.1:" + serverPort + "\r\n\r\n"));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private interface ServerAction {
        void accept(ChannelHandlerContext ctx, HttpMessage msg) throws Exception;
    }
}
