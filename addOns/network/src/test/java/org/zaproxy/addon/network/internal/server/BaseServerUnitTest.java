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
package org.zaproxy.addon.network.internal.server;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.DelimiterBasedFrameDecoder;
import io.netty.handler.codec.Delimiters;
import io.netty.handler.codec.string.StringDecoder;
import io.netty.handler.codec.string.StringEncoder;
import io.netty.util.AttributeKey;
import io.netty.util.NettyRuntime;
import io.netty.util.concurrent.DefaultThreadFactory;
import java.io.IOException;
import java.net.BindException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.channels.UnresolvedAddressException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Consumer;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configurator;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.zaproxy.addon.network.TestLogAppender;
import org.zaproxy.addon.network.internal.ChannelAttributes;
import org.zaproxy.addon.network.server.Server;
import org.zaproxy.addon.network.testutils.TestClient;
import org.zaproxy.addon.network.testutils.TextTestClient;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link BaseServer}. */
class BaseServerUnitTest extends TestUtils {

    private static NioEventLoopGroup eventLoopGroup;
    private static TestClient client;

    private BaseServer server;
    private List<Object> messagesReceived;

    @BeforeAll
    static void setupAll() throws Exception {
        eventLoopGroup =
                new NioEventLoopGroup(
                        NettyRuntime.availableProcessors(),
                        new DefaultThreadFactory("ZAP-BaseServerUnitTest"));

        String address = "127.0.0.1";
        client = new TextTestClient(address);
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
        messagesReceived = new ArrayList<>();
        createDefaultServer();
    }

    @AfterEach
    void cleanUp() throws Exception {
        if (server != null) {
            server.stop();
        }

        if (client != null) {
            client.closeChannels();
        }

        Configurator.reconfigure(getClass().getResource("/log4j2-test.properties").toURI());
    }

    private void createDefaultServer() {
        createServer(this::initDefaultChannel);
    }

    private void initDefaultChannel(SocketChannel ch) {
        ch.pipeline()
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
                        });
    }

    private void createServer(Consumer<SocketChannel> channelInitialiser) {
        server = new BaseServer(eventLoopGroup, channelInitialiser);
    }

    @Test
    void shouldThrowIfNoChannelInitialiserProvided() throws Exception {
        // Given
        Consumer<SocketChannel> channelInitialiser = null;
        // When / Then
        assertThrows(
                NullPointerException.class,
                () -> server = new BaseServer(eventLoopGroup, channelInitialiser));
    }

    @Test
    void shouldThrowIfSettingNullChannelInitialiser() throws Exception {
        // Given
        server = new BaseServer(eventLoopGroup);
        Consumer<SocketChannel> channelInitialiser = null;
        // When / Then
        assertThrows(
                NullPointerException.class, () -> server.setChannelInitialiser(channelInitialiser));
    }

    @Test
    void shouldFailToStartWithNoChannelInitialiser() throws Exception {
        // Given
        server = new BaseServer(eventLoopGroup);
        int port = getRandomPort();
        // When / Then
        assertThrows(IOException.class, () -> server.start(port));
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, Server.MAX_PORT + 1})
    void shouldThrowWhenStartingWithInvalidPort(int port) throws Exception {
        Exception e = assertThrows(IllegalArgumentException.class, () -> server.start(port));
        assertThat(e.getMessage(), containsString("Invalid port"));
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, Server.MAX_PORT + 1})
    void shouldThrowWhenStartingWithValidAddressAndInvalidPort(int port) throws Exception {
        // Given
        String validAddress = Server.DEFAULT_ADDRESS;
        // When / Then
        Exception e =
                assertThrows(
                        IllegalArgumentException.class, () -> server.start(validAddress, port));
        assertThat(e.getMessage(), containsString("Invalid port"));
    }

    @Test
    void shouldThrowWhenStartingWithUnresolvableAddress() throws Exception {
        // Given
        String address = "NotResolvableAddress_!\"#$%&";
        // When / Then
        assertThrows(UnresolvedAddressException.class, () -> server.start(address));
    }

    @Test
    void shouldThrowWhenStartingWithUsedPort() throws Exception {
        try (ServerSocket otherServer =
                new ServerSocket(0, 1, InetAddress.getByName(Server.DEFAULT_ADDRESS))) {
            // Given
            int port = otherServer.getLocalPort();
            // When / Then
            assertThrows(BindException.class, () -> server.start(port));
        }
    }

    @Test
    void shouldCloseChannelAndLogErrorIfChannelInitFails() throws Exception {
        // Given
        List<String> logEvents = registerLogEvents();
        int port = getRandomPort();
        createServer(
                ch -> {
                    throw new RuntimeException("Should cause the channel init to fail.");
                });
        server.start(port);
        // When / Then
        assertThrows(Exception.class, () -> client.send(port, "Message"));
        synchronized (logEvents) {
            assertThat(
                    logEvents,
                    hasItem(
                            startsWith(
                                    "ERROR An error occurred while initializing the channel. Closing:")));
        }
    }

    @Test
    void shouldAddALocalAddressAttributeToChannel() throws Exception {
        // Given
        createServer(
                ch -> {
                    assertChannelAttribute(ch, ChannelAttributes.LOCAL_ADDRESS, ch.localAddress());
                    initDefaultChannel(ch);
                });
        int port = getRandomPort();
        server.start(port);
        // When / Then
        client.send(port, "Message");
    }

    @Test
    void shouldAddRemoteAddressAttributeToChannel() throws Exception {
        // Given
        createServer(
                ch -> {
                    assertChannelAttribute(ch, ChannelAttributes.LOCAL_ADDRESS, ch.localAddress());
                    initDefaultChannel(ch);
                });
        int port = getRandomPort();
        server.start(port);
        // When / Then
        client.send(port, "Message");
    }

    @Test
    void shouldAddTlsUpgradedAttributeToChannel() throws Exception {
        // Given
        createServer(
                ch -> {
                    assertChannelAttribute(ch, ChannelAttributes.TLS_UPGRADED, Boolean.FALSE);
                    initDefaultChannel(ch);
                });
        int port = getRandomPort();
        server.start(port);
        // When / Then
        client.send(port, "Message");
    }

    @Test
    void shouldAddProcessingMessageAttributeToChannel() throws Exception {
        // Given
        createServer(
                ch -> {
                    assertChannelAttribute(ch, ChannelAttributes.PROCESSING_MESSAGE, Boolean.FALSE);
                    initDefaultChannel(ch);
                });
        int port = getRandomPort();
        server.start(port);
        // When / Then
        client.send(port, "Message");
    }

    @Test
    void shouldStartServerOnSpecifiedPort() throws Exception {
        // Given
        int port = getRandomPort();
        String message = "Message";
        // When
        server.start(port);
        client.send(port, message);
        // Then
        assertThat(messagesReceived, contains(message));
        assertThat(server.isStarted(), is(equalTo(true)));
    }

    @Test
    void shouldStartServerOnRandomPort() throws Exception {
        // Given / When
        int port = server.start(Server.ANY_PORT);
        String message = "Message";
        client.send(port, message);
        // Then
        assertThat(messagesReceived, contains(message));
        assertThat(server.isStarted(), is(equalTo(true)));
    }

    @Test
    void shouldStartServerOnSpecifiedAddress() throws Exception {
        // Given
        String address = "127.0.0.1";
        String message = "Message";
        // When
        int port = server.start(address);
        client.send(port, message);
        // Then
        assertThat(messagesReceived, contains(message));
        assertThat(server.isStarted(), is(equalTo(true)));
    }

    @Test
    void shouldStopServer() throws Exception {
        // Given
        int port = server.start(Server.ANY_PORT);
        String message = "Message 1";
        client.send(port, message);
        // When
        server.stop();
        // Then
        assertThrows(IOException.class, () -> client.send(port, "Message 2"));
        assertThat(messagesReceived, contains(message));
        assertThat(server.isStarted(), is(equalTo(false)));
    }

    @Test
    void shouldStopServerOnClose() throws Exception {
        // Given
        int port = server.start(Server.ANY_PORT);
        String message = "Message 1";
        client.send(port, message);
        // When
        server.close();
        // Then
        assertThrows(IOException.class, () -> client.send(port, "Message 2"));
        assertThat(messagesReceived, contains(message));
        assertThat(server.isStarted(), is(equalTo(false)));
    }

    @Test
    void shouldBeAutoCloseable() throws Exception {
        // Given
        int port;
        String message = "Message 1";
        try (BaseServer server = new BaseServer(eventLoopGroup, this::initDefaultChannel)) {
            port = server.start(Server.ANY_PORT);
            client.send(port, message);
            // When auto closed
        }
        // Then
        assertThrows(IOException.class, () -> client.send(port, "Message 2"));
        assertThat(messagesReceived, contains(message));
        assertThat(server.isStarted(), is(equalTo(false)));
    }

    @Test
    @Timeout(5)
    void shouldStopBeforeStartServer() throws Exception {
        // Given
        int port = server.start(Server.ANY_PORT);
        client.connect(port, "");
        assertThat(client.getChannelsCount(), is(equalTo(1)));
        // When
        server.start(port);
        // Then
        client.waitChannelsClosed();
        assertThat(client.getChannelsCount(), is(equalTo(0)));
        assertThat(server.isStarted(), is(equalTo(true)));
    }

    @Test
    @Timeout(5)
    void shouldStopServerAndActiveConnections() throws Exception {
        // Given
        int port = server.start(Server.ANY_PORT);
        String message1 = "Message 1";
        client.send(port, message1);
        String message2 = "Message 2";
        client.connect(port, message2);
        String message3 = "Message 3";
        client.connect(port, message3);
        // When
        server.stop();
        // Then
        assertThrows(IOException.class, () -> client.send(port, "Message A"));
        assertThat(messagesReceived, contains(message1, message2, message3));
        client.waitChannelsClosed();
        assertThat(client.getChannelsCount(), is(equalTo(0)));
        assertThat(server.isStarted(), is(equalTo(false)));
    }

    private static <T> void assertChannelAttribute(
            SocketChannel ch, AttributeKey<T> attr, T value) {
        assertThat(ch.hasAttr(attr), is(equalTo(true)));
        assertThat(ch.attr(attr).get(), is(equalTo(value)));
    }

    private static List<String> registerLogEvents() {
        List<String> logEvents = Collections.synchronizedList(new ArrayList<>());
        TestLogAppender logAppender = new TestLogAppender("%p %m%n", logEvents::add);
        LoggerContext context = LoggerContext.getContext();
        LoggerConfig rootLoggerconfig = context.getConfiguration().getRootLogger();
        rootLoggerconfig.getAppenders().values().forEach(context.getRootLogger()::removeAppender);
        rootLoggerconfig.addAppender(logAppender, null, null);
        rootLoggerconfig.setLevel(Level.ALL);
        context.updateLoggers();
        return logEvents;
    }
}
