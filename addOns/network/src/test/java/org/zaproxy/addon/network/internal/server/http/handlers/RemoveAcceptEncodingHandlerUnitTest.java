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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

/** Unit test for {@link RemoveAcceptEncodingHandler}. */
class RemoveAcceptEncodingHandlerUnitTest {

    private HttpMessageHandlerContext ctx;
    private HttpRequestHeader requestHeader;
    private HttpMessage message;
    private HandlerState state;
    private RemoveAcceptEncodingHandler handler;

    @BeforeEach
    void setUp() {
        ctx = mock(HttpMessageHandlerContext.class);
        given(ctx.isFromClient()).willReturn(true);
        message = mock(HttpMessage.class);
        requestHeader = mock(HttpRequestHeader.class);
        given(message.getRequestHeader()).willReturn(requestHeader);
        state = mock(HandlerState.class);
        given(state.isEnabled()).willReturn(true);
        handler = new RemoveAcceptEncodingHandler(state);
    }

    @Test
    void shouldNotHandleExcludedMessage() throws Exception {
        // Given
        given(ctx.isExcluded()).willReturn(true);
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(message, times(0)).getRequestHeader();
    }

    @Test
    void shouldNotHandleResponse() throws Exception {
        // Given
        given(ctx.isFromClient()).willReturn(false);
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(message, times(0)).getRequestHeader();
    }

    @Test
    void shouldNotRemoveHeaderIfNotPresent() throws Exception {
        // Given
        given(requestHeader.getHeader(HttpHeader.ACCEPT_ENCODING)).willReturn(null);
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(requestHeader, times(0)).setHeader(any(), any());
    }

    @Test
    void shouldRemoveHeaderIfPresent() throws Exception {
        // Given
        given(requestHeader.getHeader(HttpHeader.ACCEPT_ENCODING)).willReturn("gzip");
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(requestHeader).setHeader(HttpHeader.ACCEPT_ENCODING, null);
    }

    @Test
    void shouldRemoveHeaderWithAlwaysEnabledInstance() throws Exception {
        // Given
        given(requestHeader.getHeader(HttpHeader.ACCEPT_ENCODING)).willReturn("gzip");
        handler = RemoveAcceptEncodingHandler.getEnabledInstance();
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(requestHeader).setHeader(HttpHeader.ACCEPT_ENCODING, null);
    }

    @Test
    void shouldNotRemoveHeaderIfDisabled() throws Exception {
        // Given
        given(requestHeader.getHeader(HttpHeader.ACCEPT_ENCODING)).willReturn(null);
        given(state.isEnabled()).willReturn(false);
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(requestHeader, times(0)).setHeader(any(), any());
    }
}
