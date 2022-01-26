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
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.sameInstance;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.embedded.EmbeddedChannel;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.network.internal.ChannelAttributes;
import org.zaproxy.addon.network.internal.codec.HttpRequestDecoder;

/** Unit test for {@link ConnectRequestHandler}. */
class ConnectRequestHandlerUnitTest {

    private static final InetSocketAddress SENDER_ADDRESS =
            new InetSocketAddress("127.0.0.1", 1234);

    private List<HttpMessage> messagesReceived;
    private List<HttpMessage> messagesProcessed;
    private List<Throwable> exceptionsThrown;

    private EmbeddedChannel channel;

    @BeforeEach
    void setUp() {
        messagesReceived = new ArrayList<>();
        messagesProcessed = new ArrayList<>();
        exceptionsThrown = new ArrayList<>();

        channel =
                new EmbeddedChannel(
                        new HttpRequestDecoder(),
                        new SimpleChannelInboundHandler<HttpMessage>() {

                            @Override
                            protected void channelRead0(ChannelHandlerContext ctx, HttpMessage msg)
                                    throws Exception {
                                messagesReceived.add(msg);
                                ctx.fireChannelRead(msg);
                            }
                        },
                        ConnectRequestHandler.getInstance(),
                        new SimpleChannelInboundHandler<HttpMessage>() {

                            @Override
                            protected void channelRead0(ChannelHandlerContext ctx, HttpMessage msg)
                                    throws Exception {
                                messagesProcessed.add(msg);
                            }

                            @Override
                            public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause)
                                    throws Exception {
                                exceptionsThrown.add(cause);
                            }
                        });
        channel.attr(ChannelAttributes.TLS_UPGRADED).set(Boolean.FALSE);
        channel.attr(ChannelAttributes.REMOTE_ADDRESS).set(SENDER_ADDRESS);
    }

    @Test
    void shouldBeSharable() {
        assertThat(new ConnectRequestHandler().isSharable(), is(equalTo(true)));
    }

    @Test
    void shouldThrowExceptionInDecodedHttpMessage() throws Exception {
        // Given
        String request = "MalformedRequest HTTP/1.1\r\n\r\n";
        // When
        written(request);
        // Then
        assertThat(messagesReceived, hasSize(1));
        assertThat(messagesProcessed, hasSize(0));
        assertThat(exceptionsThrown, hasSize(1));
        Object exception = messagesReceived.get(0).getUserObject();
        assertThat(exceptionsThrown.get(0), is(sameInstance(exception)));
    }

    @Test
    void shouldRemoveItselfWithoutAddingTlsProtocolHandlerIfNotConnect() throws Exception {
        // Given
        String request = "GET / HTTP/1.1\r\n\r\n";
        // When
        written(request);
        // Then
        ChannelPipeline pipeline = channel.pipeline();
        assertThat(pipeline.get(ConnectRequestHandler.class), is(nullValue()));
        assertThat(pipeline.get(TlsProtocolHandler.class), is(nullValue()));
        assertThat(messagesReceived, hasSize(1));
        assertThat(messagesProcessed, hasSize(1));
        assertThat(exceptionsThrown, hasSize(0));
    }

    @Test
    void shouldRemoveItselfAndAddTlsProtocolHandlerIfConnect() throws Exception {
        // Given
        String request = "CONNECT example.org:443 HTTP/1.1\r\n\r\n";
        // When
        written(request);
        // Then
        ChannelPipeline pipeline = channel.pipeline();
        assertThat(pipeline.get(ConnectRequestHandler.class), is(nullValue()));
        TlsProtocolHandler tlsProtocolHandler = pipeline.get(TlsProtocolHandler.class);
        assertThat(tlsProtocolHandler, is(notNullValue()));
        assertThat(tlsProtocolHandler.getAuthority(), is(equalTo("example.org")));
        assertThat(messagesReceived, hasSize(1));
        assertThat(messagesProcessed, hasSize(1));
        assertThat(exceptionsThrown, hasSize(0));
    }

    private void written(String content) {
        ByteBuf buf = Unpooled.copiedBuffer(content, StandardCharsets.US_ASCII);
        assertThat(channel.writeInbound(buf), is(equalTo(false)));
    }
}
