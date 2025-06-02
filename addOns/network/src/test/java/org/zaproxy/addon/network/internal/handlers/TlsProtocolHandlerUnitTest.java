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
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.DelimiterBasedFrameDecoder;
import io.netty.handler.codec.Delimiters;
import io.netty.handler.codec.string.StringDecoder;
import io.netty.handler.codec.string.StringEncoder;
import io.netty.handler.ssl.ApplicationProtocolConfig;
import io.netty.handler.ssl.ApplicationProtocolConfig.Protocol;
import io.netty.handler.ssl.ApplicationProtocolConfig.SelectedListenerFailureBehavior;
import io.netty.handler.ssl.ApplicationProtocolConfig.SelectorFailureBehavior;
import io.netty.handler.ssl.ApplicationProtocolNegotiationHandler;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslHandler;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import io.netty.util.Attribute;
import io.netty.util.NettyRuntime;
import io.netty.util.concurrent.DefaultThreadFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.channels.ClosedChannelException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.zaproxy.addon.network.internal.ChannelAttributes;
import org.zaproxy.addon.network.internal.TlsUtils;
import org.zaproxy.addon.network.internal.cert.ServerCertificateService;
import org.zaproxy.addon.network.internal.server.BaseServer;
import org.zaproxy.addon.network.server.Server;
import org.zaproxy.addon.network.testutils.TestServerCertificateService;
import org.zaproxy.addon.network.testutils.TextTestClient;

/** Unit test for {@link TlsProtocolHandler}. */
class TlsProtocolHandlerUnitTest {

    private static final String SERVER_ADDRESS = "127.0.0.1";

    private static NioEventLoopGroup eventLoopGroup;
    private static TextTestClient client;
    private static ServerCertificateService certificateService;
    private TextTestClient clientTls;
    private BaseServer server;
    private CountDownLatch serverChannelReady;
    private CountDownLatch serverChannelException;
    private Channel serverChannel;
    private List<Object> messagesReceived;
    private TlsConfig tlsConfig;
    private PipelineConfigurator pipelineConfigurator;

    @BeforeAll
    static void setupAll() throws Exception {
        certificateService = TestServerCertificateService.createInstance();
        eventLoopGroup =
                new NioEventLoopGroup(
                        NettyRuntime.availableProcessors(),
                        new DefaultThreadFactory("ZAP-TlsProtocolHandlerUnitTest"));

        client = new TextTestClient(SERVER_ADDRESS);
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

    @AfterAll
    static void teardownAll() {
        eventLoopGroup.shutdownGracefully();
    }

    @BeforeEach
    void setUp() {
        messagesReceived = new ArrayList<>();
        tlsConfig = mock(TlsConfig.class);
        given(tlsConfig.getTlsProtocols()).willReturn(TlsUtils.getSupportedTlsProtocols());

        serverChannelReady = new CountDownLatch(1);
        createDefaultServer();
    }

    private void createClientTls(int port) throws Exception {
        createClientTls(port, null, null);
    }

    private void createClientTls(
            int port, AlpnTestHandler alpnHandler, ApplicationProtocolConfig alpnConfig) {
        clientTls =
                new TextTestClient(
                        SERVER_ADDRESS,
                        ch -> {
                            SslContext sslCtx;
                            try {
                                sslCtx =
                                        SslContextBuilder.forClient()
                                                .trustManager(InsecureTrustManagerFactory.INSTANCE)
                                                .protocols(TlsUtils.getSupportedTlsProtocols())
                                                .applicationProtocolConfig(alpnConfig)
                                                .build();
                            } catch (SSLException e) {
                                throw new RuntimeException(e);
                            }
                            SslHandler sslHandler =
                                    sslCtx.newHandler(ch.alloc(), SERVER_ADDRESS, port);
                            sslHandler.setHandshakeTimeout(5, TimeUnit.SECONDS);
                            ch.pipeline().addFirst(sslHandler);
                            if (alpnHandler != null) {
                                ch.pipeline().addLast(alpnHandler);
                            }
                        });
    }

    private void createDefaultServer() {
        createServer(this::initDefaultChannel);
    }

    private void initDefaultChannel(SocketChannel ch) {
        initDefaultChannel(ch, new TlsProtocolHandler());
    }

    private void initDefaultChannel(SocketChannel ch, TlsProtocolHandler tlsProtocolHandler) {
        ch.attr(ChannelAttributes.CERTIFICATE_SERVICE).set(certificateService);
        ch.attr(ChannelAttributes.TLS_CONFIG).set(tlsConfig);
        ch.attr(ChannelAttributes.PIPELINE_CONFIGURATOR).set(pipelineConfigurator);

        ch.pipeline()
                .addFirst(
                        new ChannelInboundHandlerAdapter() {

                            @Override
                            public void channelActive(ChannelHandlerContext ctx) throws Exception {
                                serverChannel = ctx.channel();
                                serverChannelReady.countDown();
                                super.channelActive(ctx);
                            }
                        })
                .addLast(tlsProtocolHandler)
                .addLast(new DelimiterBasedFrameDecoder(1024, Delimiters.lineDelimiter()))
                .addLast(new StringDecoder(StandardCharsets.UTF_8))
                .addLast(new StringEncoder(StandardCharsets.UTF_8))
                .addLast(
                        new SimpleChannelInboundHandler<String>() {

                            @Override
                            protected void channelRead0(ChannelHandlerContext ctx, String msg)
                                    throws Exception {
                                messagesReceived.add(msg);
                                ctx.writeAndFlush("OK\n");
                            }

                            @Override
                            public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause)
                                    throws Exception {
                                if (serverChannelException != null) {
                                    serverChannelException.await(5, TimeUnit.SECONDS);
                                }
                                ctx.close();
                            }
                        });
    }

    private void createServer(Consumer<SocketChannel> channelInitialiser) {
        server = new BaseServer(eventLoopGroup, channelInitialiser);
    }

    @AfterEach
    void teardown() throws IOException {
        server.stop();

        if (clientTls != null) {
            clientTls.close();
            clientTls = null;
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldAddHttp2PrefaceHandlerAlways(boolean alpnEnabled) throws Exception {
        // Given
        TlsProtocolHandler handler = new TlsProtocolHandler();
        ChannelHandlerContext ctx = mock(ChannelHandlerContext.class);
        ChannelPipeline pipeline = mock(ChannelPipeline.class);
        withAlpnEnabled(ctx, pipeline, alpnEnabled);
        // When
        handler.handlerAdded(ctx);
        // Then
        verify(pipeline).addAfter(any(), eq("http2.preface"), any());
        verifyNoMoreInteractions(pipeline);
    }

    @Test
    void shouldRemoveHttp2PrefaceHandlerIfProtocolNegotiated() throws Exception {
        // Given
        int port = server.start(Server.ANY_PORT);
        String protocol = "h0";
        createClientTls(port, new AlpnTestHandler(), createAlpnConfig(protocol));
        given(tlsConfig.isAlpnEnabled()).willReturn(true);
        given(tlsConfig.getApplicationProtocols()).willReturn(List.of(protocol));
        // When
        clientTls.connect(port, "");
        // Then
        assertThat(serverChannel.pipeline().get("http2.preface"), is(nullValue()));
    }

    @Test
    void shouldNotRemoveHttp2PrefaceHandlerIfNoProtocolNegotiated() throws Exception {
        // Given
        int port = server.start(Server.ANY_PORT);
        createClientTls(port, new AlpnTestHandler(), createAlpnConfig("h0"));
        given(tlsConfig.isAlpnEnabled()).willReturn(true);
        given(tlsConfig.getApplicationProtocols()).willReturn(List.of("different-protocol"));
        serverChannelException = new CountDownLatch(1);
        // When
        assertThrows(SSLHandshakeException.class, () -> clientTls.connect(port, ""));
        // Then
        assertThat(serverChannel.pipeline().get("http2.preface"), is(notNullValue()));
        serverChannelException.countDown();
    }

    @Test
    void shouldFailIfNoCertificateService() throws Exception {
        // Given
        createServer(
                ch -> {
                    initDefaultChannel(ch);
                    ch.attr(ChannelAttributes.CERTIFICATE_SERVICE).set(null);
                });
        int port = server.start(Server.ANY_PORT);
        createClientTls(port);
        String message = "Attempting to send securily.";
        // When / Then
        assertThrows(ClosedChannelException.class, () -> clientTls.connect(port, message));
        assertThat(messagesReceived, is(empty()));
    }

    @Test
    void shouldFailIfNoTlsConfig() throws Exception {
        // Given
        createServer(
                ch -> {
                    initDefaultChannel(ch);
                    ch.attr(ChannelAttributes.TLS_CONFIG).set(null);
                });
        int port = server.start(Server.ANY_PORT);
        createClientTls(port);
        String message = "Attempting to send securily.";
        // When
        assertThrows(ClosedChannelException.class, () -> clientTls.connect(port, message));
        assertThat(messagesReceived, is(empty()));
    }

    @Test
    void shouldFailIfNoLocalAddress() throws Exception {
        // Given
        createServer(
                ch -> {
                    initDefaultChannel(ch);
                    ch.attr(ChannelAttributes.LOCAL_ADDRESS).set(null);
                });
        int port = server.start(Server.ANY_PORT);
        createClientTls(port);
        String message = "Attempting to send securily.";
        // When
        assertThrows(ClosedChannelException.class, () -> clientTls.connect(port, message));
        assertThat(messagesReceived, is(empty()));
    }

    @Test
    void shouldRemoveItselfWithoutAddingSslHandlerIfNotTlsData() throws Exception {
        // Given
        int port = server.start(Server.ANY_PORT);
        String message = "Sending plain text.";
        // When
        client.connect(port, message);
        // Then
        waitForServerChannel();
        ChannelPipeline pipeline = serverChannel.pipeline();
        assertThat(pipeline.get(TlsProtocolHandler.class), is(nullValue()));
        assertThat(pipeline.get(SslHandler.class), is(nullValue()));
        assertThat(messagesReceived, contains(message));
    }

    @Test
    void shouldWaitForEnoughDataToDecideRemoveItself() throws Exception {
        // Given
        int port = server.start(Server.ANY_PORT);
        Channel clientChannel = client.connect(port, null);
        // When
        clientChannel.writeAndFlush("1").sync();
        waitForServerChannel();
        ChannelPipeline pipeline = serverChannel.pipeline();
        assertThat(pipeline.get(TlsProtocolHandler.class), is(notNullValue()));
        clientChannel.writeAndFlush("2345\n").sync();
        TextTestClient.waitForResponse(clientChannel);
        // Then
        assertThat(pipeline.get(TlsProtocolHandler.class), is(nullValue()));
        assertThat(pipeline.get(SslHandler.class), is(nullValue()));
        assertThat(messagesReceived, contains("12345"));
    }

    @Test
    void shouldRemoveItselfAndAddSslHandlerIfTlsData() throws Exception {
        // Given
        int port = server.start(Server.ANY_PORT);
        createClientTls(port);
        String message = "Sending securily.";
        // When
        clientTls.connect(port, message);
        // Then
        waitForServerChannel();
        ChannelPipeline pipeline = serverChannel.pipeline();
        assertThat(pipeline.get(TlsProtocolHandler.class), is(nullValue()));
        assertThat(pipeline.get(SslHandler.class), is(notNullValue()));
        assertThat(messagesReceived, contains(message));
    }

    @Test
    void shouldAddSslHandlerWithExpectedName() throws Exception {
        // Given
        int port = server.start(Server.ANY_PORT);
        createClientTls(port);
        String message = "Sending securily.";
        // When
        clientTls.connect(port, message);
        // Then
        waitForServerChannel();
        ChannelPipeline pipeline = serverChannel.pipeline();
        assertThat(pipeline.get(TlsProtocolHandler.TLS_HANDLER_NAME), is(notNullValue()));
    }

    @Test
    void shouldSetTlsUpgradedToFalseIfNotUpgraded() throws Exception {
        // Given
        int port = server.start(Server.ANY_PORT);
        String message = "Sending plain text.";
        // When
        client.send(port, message);
        // Then
        waitForServerChannel();
        assertTrue(Boolean.FALSE.equals(serverChannel.attr(ChannelAttributes.TLS_UPGRADED).get()));
        assertThat(messagesReceived, contains(message));
    }

    @Test
    void shouldSetTlsUpgradedToTrueIfUpgraded() throws Exception {
        // Given
        int port = server.start(Server.ANY_PORT);
        createClientTls(port);
        String message = "Sending securily.";
        // When
        clientTls.connect(port, message);
        // Then
        waitForServerChannel();
        assertTrue(Boolean.TRUE.equals(serverChannel.attr(ChannelAttributes.TLS_UPGRADED).get()));
        assertThat(messagesReceived, contains(message));
    }

    @Test
    void shouldUseProtocolsFromTlsConfig() throws Exception {
        // Given
        int port = server.start(Server.ANY_PORT);
        createClientTls(port);
        // Not allowing any will lead to exception.
        given(tlsConfig.getTlsProtocols()).willReturn(Collections.emptyList());
        String message = "Attempting to send securily.";
        // When / Then
        assertThrows(Exception.class, () -> clientTls.connect(port, message));
        assertThat(messagesReceived, is(empty()));
    }

    @Test
    void shouldUseProvidedAuthorityForCert() throws Exception {
        // Given
        createServer(ch -> initDefaultChannel(ch, new TlsProtocolHandler("example.org")));
        int port = server.start(Server.ANY_PORT);
        createClientTls(port);
        String message = "Sending securily.";
        // When
        Channel clientChannel = clientTls.connect(port, message);
        // Then
        assertThat(getCertificate(clientChannel).toString(), containsString("CN=example.org"));
    }

    @Test
    void shouldUseProvidedLocalAddressForCert() throws Exception {
        // Given
        String localAddress = "127.0.1.2";
        createServer(
                ch -> {
                    initDefaultChannel(ch);
                    try {
                        ch.attr(ChannelAttributes.LOCAL_ADDRESS)
                                .set(
                                        new InetSocketAddress(
                                                InetAddress.getByName(localAddress), 1234));
                    } catch (UnknownHostException e) {
                        throw new RuntimeException(e);
                    }
                });
        int port = server.start(Server.ANY_PORT);
        createClientTls(port);
        String message = "Sending securily.";
        // When
        Channel clientChannel = clientTls.connect(port, message);
        // Then
        assertThat(getCertificate(clientChannel), containsString("IPAddress: " + localAddress));
    }

    @Test
    void shouldUseAlpnIfEnabled() throws Exception {
        // Given
        int port = server.start(Server.ANY_PORT);
        AlpnTestHandler alpnHandler = new AlpnTestHandler();
        String commonProtocol = "h0";
        createClientTls(
                port, alpnHandler, createAlpnConfig(commonProtocol, "another-protocol-client"));
        given(tlsConfig.isAlpnEnabled()).willReturn(true);
        given(tlsConfig.getApplicationProtocols())
                .willReturn(List.of(commonProtocol, "another-protocol-server"));
        // When
        clientTls.connect(port, "");
        // Then
        assertThat(alpnHandler.getNegotiatedProtocol(), is(equalTo(commonProtocol)));
    }

    @Test
    void shouldNotUseAlpnIfNotEnabled() throws Exception {
        // Given
        int port = server.start(Server.ANY_PORT);
        AlpnTestHandler alpnHandler = new AlpnTestHandler();
        String commonProtocol = "h0";
        createClientTls(
                port, alpnHandler, createAlpnConfig(commonProtocol, "another-protocol-client"));
        given(tlsConfig.isAlpnEnabled()).willReturn(false);
        given(tlsConfig.getApplicationProtocols())
                .willReturn(List.of(commonProtocol, "another-protocol-server"));
        // When
        clientTls.connect(port, "");
        // Then
        assertThat(alpnHandler.getNegotiatedProtocol(), is(AlpnTestHandler.NO_PROTOCOL_NEGOTIATED));
    }

    @Test
    void shouldFailHandshakeIfNoCommonProtocolWithAlpnEnabled() throws Exception {
        // Given
        int port = server.start(Server.ANY_PORT);
        createClientTls(port, new AlpnTestHandler(), createAlpnConfig("h0"));
        given(tlsConfig.isAlpnEnabled()).willReturn(true);
        given(tlsConfig.getApplicationProtocols()).willReturn(List.of("different-protocol"));
        // When / Then
        SSLHandshakeException e =
                assertThrows(SSLHandshakeException.class, () -> clientTls.connect(port, ""));
        assertThat(e.getMessage(), containsString("no_application_protocol"));
    }

    @Test
    void shouldCallPipelineConfiguratorAfterProtocolNegotiation() throws Exception {
        // Given
        int port = server.start(Server.ANY_PORT);
        String protocol = "h0";
        createClientTls(port, new AlpnTestHandler(), createAlpnConfig(protocol));
        given(tlsConfig.isAlpnEnabled()).willReturn(true);
        given(tlsConfig.getApplicationProtocols()).willReturn(List.of(protocol));
        pipelineConfigurator = mock(PipelineConfigurator.class);
        // When
        clientTls.connect(port, "");
        // Then
        verify(pipelineConfigurator).configure(any(), eq(protocol));
    }

    @Test
    void shouldCallPipelineConfiguratorWithProvidedFallbackIfNoProtocolNegotiated()
            throws Exception {
        // Given
        int port = server.start(Server.ANY_PORT);
        createClientTls(port);
        given(tlsConfig.isAlpnEnabled()).willReturn(true);
        given(tlsConfig.getApplicationProtocols()).willReturn(List.of("some-protocol"));
        pipelineConfigurator = mock(PipelineConfigurator.class);
        // When
        clientTls.connect(port, "");
        // Then
        verify(pipelineConfigurator).configure(any(), eq(TlsUtils.APPLICATION_PROTOCOL_HTTP_1_1));
    }

    @Test
    void shouldNotCallPipelineConfiguratorIfNoProtocolNegotiatedAndNoFallback() throws Exception {
        // Given
        int port = server.start(Server.ANY_PORT);
        createClientTls(port, new AlpnTestHandler(), createAlpnConfig("h0"));
        given(tlsConfig.isAlpnEnabled()).willReturn(true);
        given(tlsConfig.getApplicationProtocols()).willReturn(List.of("different-protocol"));
        pipelineConfigurator = mock(PipelineConfigurator.class);
        // When
        assertThrows(SSLHandshakeException.class, () -> clientTls.connect(port, ""));
        // Then
        verify(pipelineConfigurator, times(0)).configure(any(), any());
    }

    private void waitForServerChannel() throws InterruptedException {
        serverChannelReady.await(5, TimeUnit.SECONDS);
        assertThat(serverChannel, is(notNullValue()));
    }

    private static String getCertificate(Channel clientChannel) throws Exception {
        return clientChannel
                .pipeline()
                .get(SslHandler.class)
                .engine()
                .getSession()
                .getPeerCertificates()[0]
                .toString();
    }

    private static ApplicationProtocolConfig createAlpnConfig(String... protocols) {
        return new ApplicationProtocolConfig(
                Protocol.ALPN,
                SelectorFailureBehavior.NO_ADVERTISE,
                SelectedListenerFailureBehavior.ACCEPT,
                protocols);
    }

    private static void withAlpnEnabled(
            ChannelHandlerContext ctx, ChannelPipeline pipeline, boolean enabled) {
        given(ctx.pipeline()).willReturn(pipeline);
        Channel channel = mock(Channel.class);
        given(ctx.channel()).willReturn(channel);
        @SuppressWarnings("unchecked")
        Attribute<TlsConfig> attribute = mock(Attribute.class);
        given(channel.attr(ChannelAttributes.TLS_CONFIG)).willReturn(attribute);
        TlsConfig tlsConfig = mock(TlsConfig.class);
        given(attribute.get()).willReturn(tlsConfig);
        given(tlsConfig.isAlpnEnabled()).willReturn(enabled);
    }

    private static class AlpnTestHandler extends ApplicationProtocolNegotiationHandler {

        private static final String NO_PROTOCOL_NEGOTIATED = "no-protocol-negotiated";

        private String negotiatedProtocol;

        AlpnTestHandler() {
            super(NO_PROTOCOL_NEGOTIATED);
        }

        String getNegotiatedProtocol() {
            return negotiatedProtocol;
        }

        @Override
        protected void configurePipeline(ChannelHandlerContext ctx, String protocol)
                throws Exception {
            negotiatedProtocol = protocol;
        }
    }
}
