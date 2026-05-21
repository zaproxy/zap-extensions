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
package org.zaproxy.addon.network.internal;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.hasSize;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.handler.codec.http2.DefaultHttp2Connection;
import io.netty.handler.ssl.ApplicationProtocolConfig;
import io.netty.handler.ssl.ApplicationProtocolConfig.Protocol;
import io.netty.handler.ssl.ApplicationProtocolConfig.SelectedListenerFailureBehavior;
import io.netty.handler.ssl.ApplicationProtocolConfig.SelectorFailureBehavior;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import io.netty.util.NettyRuntime;
import io.netty.util.concurrent.DefaultThreadFactory;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.network.internal.cert.ServerCertificateService;
import org.zaproxy.addon.network.internal.codec.HttpToHttp2ConnectionHandler;
import org.zaproxy.addon.network.internal.codec.InboundHttp2ToHttpAdapter;
import org.zaproxy.addon.network.internal.handlers.TlsConfig;
import org.zaproxy.addon.network.internal.handlers.TlsProtocolHandler;
import org.zaproxy.addon.network.internal.server.BaseServer;
import org.zaproxy.addon.network.server.Server;
import org.zaproxy.addon.network.testutils.TestClient;
import org.zaproxy.addon.network.testutils.TestServerCertificateService;

/**
 * Tests for HTTP/2 over TLS combining {@link TlsProtocolHandler} and {@link
 * HttpToHttp2ConnectionHandler}.
 */
class Http2OverTlsUnitTest {

    private static final String SERVER_ADDRESS = "127.0.0.1";

    private static NioEventLoopGroup eventLoopGroup;
    private static ServerCertificateService certificateService;

    private TlsConfig tlsConfig;
    private BaseServer server;
    private TestClient client;
    private List<HttpMessage> serverRequests;
    private List<HttpMessage> clientResponses;
    private CountDownLatch responseReceived;

    @BeforeAll
    static void setupAll() {
        certificateService = TestServerCertificateService.createInstance();
        eventLoopGroup =
                new NioEventLoopGroup(
                        NettyRuntime.availableProcessors(),
                        new DefaultThreadFactory("ZAP-Http2OverTlsUnitTest"));
    }

    @AfterAll
    static void tearDownAll() {
        if (eventLoopGroup != null) {
            eventLoopGroup.shutdownGracefully();
            eventLoopGroup = null;
        }
    }

    @BeforeEach
    void setUp() {
        serverRequests = new ArrayList<>();
        clientResponses = new ArrayList<>();
        responseReceived = new CountDownLatch(1);
        tlsConfig = mock(TlsConfig.class);
        given(tlsConfig.getTlsProtocols()).willReturn(TlsUtils.getSupportedTlsProtocols());
    }

    @AfterEach
    void teardown() throws IOException {
        if (server != null) {
            server.stop();
            server = null;
        }
        if (client != null) {
            client.close();
            client = null;
        }
    }

    @Test
    void shouldExchangeHttpRequestResponseOverHttp2AndTls() throws Exception {
        // Given
        given(tlsConfig.isAlpnEnabled()).willReturn(true);
        given(tlsConfig.getApplicationProtocols())
                .willReturn(List.of(TlsUtils.APPLICATION_PROTOCOL_HTTP_2));

        server =
                new BaseServer(
                        eventLoopGroup,
                        ch -> {
                            ch.attr(ChannelAttributes.CERTIFICATE_SERVICE).set(certificateService);
                            ch.attr(ChannelAttributes.TLS_CONFIG).set(tlsConfig);
                            ch.attr(ChannelAttributes.PIPELINE_CONFIGURATOR)
                                    .set(
                                            (ctx, protocol) -> {
                                                DefaultHttp2Connection conn =
                                                        new DefaultHttp2Connection(true);
                                                ctx.pipeline()
                                                        .addLast(
                                                                HttpToHttp2ConnectionHandler.create(
                                                                        new InboundHttp2ToHttpAdapter(
                                                                                conn),
                                                                        null,
                                                                        conn,
                                                                        HttpHeader.HTTP),
                                                                new SimpleChannelInboundHandler<
                                                                        HttpMessage>() {
                                                                    @Override
                                                                    protected void channelRead0(
                                                                            ChannelHandlerContext c,
                                                                            HttpMessage m)
                                                                            throws Exception {
                                                                        serverRequests.add(m);
                                                                        m.setResponseHeader(
                                                                                "HTTP/2 200");
                                                                        c.writeAndFlush(m);
                                                                    }

                                                                    @Override
                                                                    public void exceptionCaught(
                                                                            ChannelHandlerContext c,
                                                                            Throwable cause) {
                                                                        c.close();
                                                                    }
                                                                });
                                            });
                            ch.pipeline().addLast(new TlsProtocolHandler());
                        });

        int port = server.start(Server.ANY_PORT);

        client = createH2TlsClient(port, TlsUtils.APPLICATION_PROTOCOL_HTTP_2);

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(
                new HttpRequestHeader("GET http://" + SERVER_ADDRESS + ":" + port + "/ HTTP/2"));

        // When
        Channel channel = client.connect(port, msg);

        // Then
        waitForResponse();
        assertThat(serverRequests, hasSize(1));
        assertThat(clientResponses, hasSize(1));
        assertThat(clientResponses.get(0).getResponseHeader().getStatusCode(), is(equalTo(200)));

        channel.close().sync();
    }

    @Test
    void shouldExchangeMultipleRequestsOverHttp2AndTls() throws Exception {
        // Given
        given(tlsConfig.isAlpnEnabled()).willReturn(true);
        given(tlsConfig.getApplicationProtocols())
                .willReturn(List.of(TlsUtils.APPLICATION_PROTOCOL_HTTP_2));

        server =
                new BaseServer(
                        eventLoopGroup,
                        ch -> {
                            ch.attr(ChannelAttributes.CERTIFICATE_SERVICE).set(certificateService);
                            ch.attr(ChannelAttributes.TLS_CONFIG).set(tlsConfig);
                            ch.attr(ChannelAttributes.PIPELINE_CONFIGURATOR)
                                    .set(
                                            (ctx, protocol) -> {
                                                DefaultHttp2Connection conn =
                                                        new DefaultHttp2Connection(true);
                                                ctx.pipeline()
                                                        .addLast(
                                                                HttpToHttp2ConnectionHandler.create(
                                                                        new InboundHttp2ToHttpAdapter(
                                                                                conn),
                                                                        null,
                                                                        conn,
                                                                        HttpHeader.HTTP),
                                                                new SimpleChannelInboundHandler<
                                                                        HttpMessage>() {
                                                                    @Override
                                                                    protected void channelRead0(
                                                                            ChannelHandlerContext c,
                                                                            HttpMessage m)
                                                                            throws Exception {
                                                                        serverRequests.add(m);
                                                                        m.setResponseHeader(
                                                                                "HTTP/2 200");
                                                                        c.writeAndFlush(m);
                                                                    }

                                                                    @Override
                                                                    public void exceptionCaught(
                                                                            ChannelHandlerContext c,
                                                                            Throwable cause) {
                                                                        c.close();
                                                                    }
                                                                });
                                            });
                            ch.pipeline().addLast(new TlsProtocolHandler());
                        });

        int port = server.start(Server.ANY_PORT);

        client = createH2TlsClient(port, TlsUtils.APPLICATION_PROTOCOL_HTTP_2);

        HttpMessage msg1 = new HttpMessage();
        msg1.setRequestHeader(
                new HttpRequestHeader("GET http://" + SERVER_ADDRESS + ":" + port + "/ HTTP/2"));
        HttpMessage msg2 = new HttpMessage();
        msg2.setRequestHeader(
                new HttpRequestHeader(
                        "GET http://" + SERVER_ADDRESS + ":" + port + "/second HTTP/2"));
        responseReceived = new CountDownLatch(2);

        // When
        Channel channel = client.connect(port, msg1);
        waitForResponse();
        responseReceived = new CountDownLatch(1);
        channel.writeAndFlush(msg2).sync();
        waitForResponse();

        // Then
        assertThat(serverRequests, hasSize(2));
        assertThat(clientResponses, hasSize(2));
        assertThat(clientResponses.get(0).getResponseHeader().getStatusCode(), is(equalTo(200)));
        assertThat(clientResponses.get(1).getResponseHeader().getStatusCode(), is(equalTo(200)));

        channel.close().sync();
    }

    @Test
    void shouldFallbackToHttp11WhenClientOnlyOffersHttp11() throws Exception {
        // Given
        given(tlsConfig.isAlpnEnabled()).willReturn(true);
        given(tlsConfig.getApplicationProtocols())
                .willReturn(
                        List.of(
                                TlsUtils.APPLICATION_PROTOCOL_HTTP_2,
                                TlsUtils.APPLICATION_PROTOCOL_HTTP_1_1));

        CountDownLatch alpnDone = new CountDownLatch(1);
        List<String> configuredProtocols = new ArrayList<>();
        server =
                new BaseServer(
                        eventLoopGroup,
                        ch -> {
                            ch.attr(ChannelAttributes.CERTIFICATE_SERVICE).set(certificateService);
                            ch.attr(ChannelAttributes.TLS_CONFIG).set(tlsConfig);
                            ch.attr(ChannelAttributes.PIPELINE_CONFIGURATOR)
                                    .set(
                                            (ctx, protocol) -> {
                                                configuredProtocols.add(protocol);
                                                alpnDone.countDown();
                                            });
                            ch.pipeline().addLast(new TlsProtocolHandler());
                        });

        int port = server.start(Server.ANY_PORT);

        client = createTlsOnlyClient(port, TlsUtils.APPLICATION_PROTOCOL_HTTP_1_1);

        // When
        client.connect(port, null);

        // Then
        assertThat(alpnDone.await(5, TimeUnit.SECONDS), is(true));
        assertThat(configuredProtocols, contains(TlsUtils.APPLICATION_PROTOCOL_HTTP_1_1));
    }

    private void waitForResponse() throws InterruptedException {
        responseReceived.await(5, TimeUnit.SECONDS);
    }

    private TestClient createH2TlsClient(int port, String alpnProtocol) {
        return new TestClient(
                SERVER_ADDRESS,
                ch -> {
                    SslContext sslCtx = buildClientSslContext(alpnProtocol);
                    DefaultHttp2Connection conn = new DefaultHttp2Connection(false);
                    ch.pipeline()
                            .addLast(sslCtx.newHandler(ch.alloc(), SERVER_ADDRESS, port))
                            .addLast(
                                    HttpToHttp2ConnectionHandler.create(
                                            new InboundHttp2ToHttpAdapter(conn),
                                            null,
                                            conn,
                                            HttpHeader.HTTP))
                            .addLast(
                                    new SimpleChannelInboundHandler<HttpMessage>() {
                                        @Override
                                        protected void channelRead0(
                                                ChannelHandlerContext c, HttpMessage m) {
                                            clientResponses.add(m);
                                            responseReceived.countDown();
                                        }

                                        @Override
                                        public void exceptionCaught(
                                                ChannelHandlerContext c, Throwable cause) {
                                            c.close();
                                        }
                                    });
                });
    }

    private TestClient createTlsOnlyClient(int port, String alpnProtocol) {
        return new TestClient(
                SERVER_ADDRESS,
                ch -> {
                    SslContext sslCtx = buildClientSslContext(alpnProtocol);
                    ch.pipeline().addLast(sslCtx.newHandler(ch.alloc(), SERVER_ADDRESS, port));
                });
    }

    private static SslContext buildClientSslContext(String alpnProtocol) {
        ApplicationProtocolConfig alpnConfig =
                new ApplicationProtocolConfig(
                        Protocol.ALPN,
                        SelectorFailureBehavior.NO_ADVERTISE,
                        SelectedListenerFailureBehavior.ACCEPT,
                        alpnProtocol);
        try {
            return SslContextBuilder.forClient()
                    .trustManager(InsecureTrustManagerFactory.INSTANCE)
                    .protocols(TlsUtils.getSupportedTlsProtocols())
                    .applicationProtocolConfig(alpnConfig)
                    .build();
        } catch (SSLException e) {
            throw new RuntimeException(e);
        }
    }
}
