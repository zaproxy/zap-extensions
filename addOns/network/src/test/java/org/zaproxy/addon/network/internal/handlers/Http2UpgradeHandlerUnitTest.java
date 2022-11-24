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

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.sameInstance;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.embedded.EmbeddedChannel;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.network.internal.ChannelAttributes;
import org.zaproxy.addon.network.internal.TlsUtils;
import org.zaproxy.addon.network.internal.codec.HttpToHttp2ConnectionHandler;

/** Unit test for {@link Http2UpgradeHandler}. */
class Http2UpgradeHandlerUnitTest {

    private int messagesReceived;
    private int messagesProcessed;
    private List<Throwable> exceptionsThrown;

    private PipelineConfigurator pipelineConfigurator;
    private boolean configuratorCalled;
    private HttpToHttp2ConnectionHandler connectionHandler;
    private HttpMessage msg;

    private EmbeddedChannel channel;

    @BeforeEach
    void setUp() {
        connectionHandler = mock(HttpToHttp2ConnectionHandler.class);
        pipelineConfigurator =
                (ctx, protocol) -> {
                    configuratorCalled = true;
                    assertThat(protocol, is(equalTo(TlsUtils.APPLICATION_PROTOCOL_HTTP_2)));
                    ctx.pipeline().addLast(connectionHandler);
                };

        msg = new HttpMessage();
        exceptionsThrown = new ArrayList<>();

        channel =
                new EmbeddedChannel(
                        new SimpleChannelInboundHandler<HttpMessage>() {

                            @Override
                            protected void channelRead0(ChannelHandlerContext ctx, HttpMessage msg)
                                    throws Exception {
                                messagesReceived++;
                                ctx.fireChannelRead(msg);
                            }
                        },
                        new Http2UpgradeHandler(),
                        new SimpleChannelInboundHandler<HttpMessage>() {

                            @Override
                            protected void channelRead0(ChannelHandlerContext ctx, HttpMessage msg)
                                    throws Exception {
                                messagesProcessed++;
                            }

                            @Override
                            public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause)
                                    throws Exception {
                                exceptionsThrown.add(cause);
                            }
                        });
        channel.attr(ChannelAttributes.PIPELINE_CONFIGURATOR).set(pipelineConfigurator);
    }

    @Test
    void shouldBeSharable() {
        assertThat(new Http2UpgradeHandler().isSharable(), is(equalTo(true)));
    }

    @Test
    void shouldThrowExceptionInHttpMessage() throws Exception {
        // Given
        Exception e = new IllegalStateException();
        msg.setUserObject(e);
        // When
        messageWritten();
        // Then
        assertThat(messagesReceived, is(equalTo(1)));
        assertThat(messagesProcessed, is(equalTo(0)));
        assertThat(exceptionsThrown, hasSize(1));
        assertThat(exceptionsThrown.get(0), is(sameInstance(e)));
    }

    @Test
    void shouldRemoveItselIfNotUpgrade() throws Exception {
        // Given
        msg.setRequestHeader("GET / HTTP/1.1");
        // When
        messageWritten();
        // Then
        ChannelPipeline pipeline = channel.pipeline();
        assertThat(pipeline.get(Http2UpgradeHandler.class), is(nullValue()));
        assertThat(messagesReceived, is(equalTo(1)));
        assertThat(messagesProcessed, is(equalTo(1)));
        assertThat(exceptionsThrown, hasSize(0));
        assertThat(configuratorCalled, is(equalTo(false)));
    }

    @Test
    void shouldNotUpgradeIfNotH2cUpgrade() throws Exception {
        // Given
        msg.setRequestHeader(
                "GET / HTTP/1.1\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade");
        // When
        messageWritten();
        // Then
        ChannelPipeline pipeline = channel.pipeline();
        assertThat(pipeline.get(Http2UpgradeHandler.class), is(nullValue()));
        assertThat(messagesReceived, is(equalTo(1)));
        assertThat(messagesProcessed, is(equalTo(1)));
        assertThat(exceptionsThrown, hasSize(0));
        assertThat(configuratorCalled, is(equalTo(false)));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "Connection: keep-alive, Upgrade",
                "Connection: Upgrade",
                "Connection: HTTP2-Settings",
                "Connection: Something",
                ""
            })
    void shouldNotUpgradeIfMissingExpectedConnectionValues(String connection) throws Exception {
        // Given
        msg.setRequestHeader("GET / HTTP/1.1\r\nUpgrade: h2c\r\n" + connection);
        // When
        messageWritten();
        // Then
        ChannelPipeline pipeline = channel.pipeline();
        assertThat(pipeline.get(Http2UpgradeHandler.class), is(nullValue()));
        assertThat(messagesReceived, is(equalTo(1)));
        assertThat(messagesProcessed, is(equalTo(1)));
        assertThat(exceptionsThrown, hasSize(0));
        assertThat(configuratorCalled, is(equalTo(false)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"HTTP2-Settings, Upgrade", "Upgrade, HTTP2-Settings"})
    void shouldNotUpgradeIfMissingHttp2SettingsHeader(String values) throws Exception {
        // Given
        msg.setRequestHeader("GET / HTTP/1.1\r\nUpgrade: h2c\r\nConnection: " + values);
        // When
        messageWritten();
        // Then
        ChannelPipeline pipeline = channel.pipeline();
        assertThat(pipeline.get(Http2UpgradeHandler.class), is(nullValue()));
        assertThat(messagesReceived, is(equalTo(1)));
        assertThat(messagesProcessed, is(equalTo(1)));
        assertThat(exceptionsThrown, hasSize(0));
        assertThat(configuratorCalled, is(equalTo(false)));
    }

    @Test
    void shouldNotUpgradeIfInvalidBase64Http2SettingsHeader() throws Exception {
        // Given
        msg.setRequestHeader(
                "GET / HTTP/1.1\r\nUpgrade: h2c\r\nConnection: Upgrade, HTTP2-Settings\r\nHTTP2-Settings: ?");
        // When
        messageWritten();
        // Then
        ChannelPipeline pipeline = channel.pipeline();
        assertThat(pipeline.get(Http2UpgradeHandler.class), is(nullValue()));
        assertThat(messagesReceived, is(equalTo(1)));
        assertThat(messagesProcessed, is(equalTo(0)));
        assertThat(exceptionsThrown, hasSize(1));
        assertThat(exceptionsThrown.get(0).getMessage(), containsString("invalid Base64 input"));
        assertThat(configuratorCalled, is(equalTo(false)));
    }

    @Test
    void shoulUpgradeIfAllConditionsMet() throws Exception {
        // Given
        msg.setRequestHeader(
                "GET / HTTP/1.1\r\nUpgrade: h2c\r\nConnection: Upgrade, HTTP2-Settings\r\nHTTP2-Settings: a");
        // When
        messageWritten();
        // Then
        ChannelPipeline pipeline = channel.pipeline();
        assertThat(pipeline.get(Http2UpgradeHandler.class), is(nullValue()));
        assertThat(messagesReceived, is(equalTo(1)));
        assertThat(messagesProcessed, is(equalTo(1)));
        assertThat(exceptionsThrown, hasSize(0));
        verify(connectionHandler).onHttpServerUpgrade(any());
        assertThat(msg.getRequestHeader().getHeader(HttpHeader.CONNECTION), is(nullValue()));
        assertThat(
                msg.getRequestHeader().getHeader(HttpHeader.PROXY_CONNECTION), is(equalTo(null)));
        assertThat(msg.getRequestHeader().getHeader("Upgrade"), is(nullValue()));
        assertThat(msg.getRequestHeader().getHeader("HTTP2-Settings"), is(equalTo(null)));
        assertThat(msg.getResponseHeader().isEmpty(), is(equalTo(true)));
    }

    private void messageWritten() {
        assertThat(channel.writeInbound(msg), is(equalTo(false)));
    }
}
