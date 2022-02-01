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
package org.zaproxy.addon.network.internal.server.http;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPipeline;
import io.netty.util.Attribute;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.addon.network.internal.ChannelAttributes;
import org.zaproxy.addon.network.internal.server.http.handlers.LegacyProxyListenerHandler;
import org.zaproxy.addon.network.server.HttpMessageHandler;
import org.zaproxy.zap.ZapGetMethod;

/** Unit test for {@link MainProxyHandler}. */
class MainProxyHandlerUnitTest {

    private ChannelHandlerContext ctx;
    private HttpResponseHeader responseHeader;
    private HttpMessage msg;
    private LegacyProxyListenerHandler legacyHandler;
    private MainProxyHandler handler;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        ctx = mock(ChannelHandlerContext.class);
        given(ctx.close()).willReturn(mock(ChannelFuture.class));
        Channel channel = mock(Channel.class);
        Attribute<Boolean> att = mock(Attribute.class);
        given(att.get()).willReturn(Boolean.FALSE);
        given(channel.attr(ChannelAttributes.TLS_UPGRADED)).willReturn(att);
        given(channel.pipeline()).willReturn(mock(ChannelPipeline.class));
        given(ctx.channel()).willReturn(channel);
        responseHeader = mock(HttpResponseHeader.class);
        msg = mock(HttpMessage.class);
        given(msg.getResponseHeader()).willReturn(responseHeader);
        legacyHandler = mock(LegacyProxyListenerHandler.class);
        handler = new MainProxyHandler(legacyHandler, Collections.emptyList());
    }

    @Test
    void shouldThrowIfLegacyHandlerIsNull() {
        // Given
        LegacyProxyListenerHandler legacyHandler = null;
        List<HttpMessageHandler> handlers = Collections.emptyList();
        // When / Then
        assertThrows(
                NullPointerException.class, () -> new MainProxyHandler(legacyHandler, handlers));
    }

    @Test
    void shouldThrowIfHandlersListIsNull() {
        // Given
        List<HttpMessageHandler> handlers = null;
        // When / Then
        assertThrows(
                NullPointerException.class, () -> new MainProxyHandler(legacyHandler, handlers));
    }

    @Test
    void shouldNotSkipIfNotUpgrade() {
        // Given
        given(responseHeader.getStatusCode()).willReturn(200);
        // When
        boolean skip = handler.postWriteResponse(ctx, msg);
        // Then
        assertThat(skip, is(equalTo(false)));
    }

    @Test
    void shouldNotSkipIfNotEventStream() {
        // Given
        given(msg.isEventStream()).willReturn(false);
        // When
        boolean skip = handler.postWriteResponse(ctx, msg);
        // Then
        assertThat(skip, is(equalTo(false)));
    }

    @Test
    void shouldSkipIfUpgradeAndConsumer() {
        // Given
        given(responseHeader.getStatusCode()).willReturn(101);
        given(legacyHandler.notifyPersistentConnectionListener(eq(msg), any(), any()))
                .willReturn(true);
        // When;
        boolean skip = handler.postWriteResponse(ctx, msg);
        // Then
        assertThat(skip, is(equalTo(true)));
    }

    @Test
    void shouldSkipIfEventStreamAndConsumer() {
        // Given
        given(msg.isEventStream()).willReturn(true);
        given(legacyHandler.notifyPersistentConnectionListener(eq(msg), any(), any()))
                .willReturn(true);
        // When
        boolean skip = handler.postWriteResponse(ctx, msg);
        // Then
        assertThat(skip, is(equalTo(true)));
    }

    @Test
    void shouldCloseAndSkipIfNoUpgradeConsumers() {
        // Given
        given(responseHeader.getStatusCode()).willReturn(101);
        given(legacyHandler.notifyPersistentConnectionListener(eq(msg), any(), any()))
                .willReturn(false);
        // When
        boolean skip = handler.postWriteResponse(ctx, msg);
        // Then
        assertThat(skip, is(equalTo(true)));
        verify(ctx).close();
    }

    @Test
    void shouldCloseAndSkipIfNoEventStreamConsumers() {
        // Given
        given(msg.isEventStream()).willReturn(true);
        given(legacyHandler.notifyPersistentConnectionListener(eq(msg), any(), any()))
                .willReturn(false);
        // When
        boolean skip = handler.postWriteResponse(ctx, msg);
        // Then
        assertThat(skip, is(equalTo(true)));
        verify(ctx).close();
    }

    @Test
    void shouldUseMethodFromMessage() {
        // Given
        given(msg.isEventStream()).willReturn(true);
        ZapGetMethod method = mock(ZapGetMethod.class);
        given(msg.getUserObject()).willReturn(method);
        // When
        handler.postWriteResponse(ctx, msg);
        // Then
        verify(legacyHandler).notifyPersistentConnectionListener(eq(msg), any(), eq(method));
    }
}
