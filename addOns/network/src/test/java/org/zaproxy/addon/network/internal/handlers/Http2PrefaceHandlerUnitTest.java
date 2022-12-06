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

import static io.netty.handler.codec.http2.Http2CodecUtil.connectionPrefaceBuf;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPipeline;
import io.netty.util.Attribute;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.network.internal.ChannelAttributes;
import org.zaproxy.addon.network.internal.TlsUtils;

/** Unit test for {@link Http2PrefaceHandler}. */
class Http2PrefaceHandlerUnitTest {

    private ChannelHandlerContext ctx;
    private ChannelPipeline pipeline;
    private ByteBuf in;
    private List<Object> out;
    private Http2PrefaceHandler handler;

    @BeforeEach
    void setUp() {
        ctx = mock(ChannelHandlerContext.class);
        pipeline = mock(ChannelPipeline.class);
        given(ctx.pipeline()).willReturn(pipeline);

        handler = new Http2PrefaceHandler();
    }

    @Test
    void shouldCallPipelineConfiguratorIfHttp2Preface() throws Exception {
        // Given
        in = connectionPrefaceBuf();
        PipelineConfigurator pipelineConfigurator = mock(PipelineConfigurator.class);
        withPipelineConfigurator(pipelineConfigurator);
        // When
        handler.decode(ctx, in, out);
        // Then
        verify(pipelineConfigurator).configure(ctx, TlsUtils.APPLICATION_PROTOCOL_HTTP_2);
    }

    @Test
    void shouldNotCallPipelineConfiguratorIfHttp2PrefaceIsNotComplete() throws Exception {
        // Given
        in = connectionPrefaceBuf().readRetainedSlice(5);
        PipelineConfigurator pipelineConfigurator = mock(PipelineConfigurator.class);
        withPipelineConfigurator(pipelineConfigurator);
        // When
        handler.decode(ctx, in, out);
        // Then
        verifyNoInteractions(pipelineConfigurator);
        verifyNoInteractions(pipeline);
    }

    @Test
    void shouldRemoveItselfIfHttp2Preface() throws Exception {
        // Given
        in = connectionPrefaceBuf();
        withPipelineConfigurator(null);
        // When
        handler.decode(ctx, in, out);
        // Then
        verify(pipeline).remove(handler);
        verifyNoMoreInteractions(pipeline);
    }

    @Test
    void shouldRemoveItselfIfNotHttp2Preface() throws Exception {
        // Given
        in = Unpooled.copiedBuffer("GET / HTTP/1.1".getBytes(StandardCharsets.US_ASCII));
        // When
        handler.decode(ctx, in, out);
        // Then
        verify(pipeline).remove(handler);
    }

    private void withPipelineConfigurator(PipelineConfigurator pipelineConfigurator) {
        Channel channel = mock(Channel.class);
        given(ctx.channel()).willReturn(channel);
        @SuppressWarnings("unchecked")
        Attribute<PipelineConfigurator> attribute = mock(Attribute.class);
        given(channel.attr(ChannelAttributes.PIPELINE_CONFIGURATOR)).willReturn(attribute);
        given(attribute.get()).willReturn(pipelineConfigurator);
    }
}
