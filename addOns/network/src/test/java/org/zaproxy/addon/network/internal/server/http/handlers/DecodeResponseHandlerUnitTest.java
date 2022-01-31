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

import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.util.Arrays;
import java.util.Collections;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;
import org.zaproxy.zap.network.HttpEncoding;
import org.zaproxy.zap.network.HttpResponseBody;

/** Unit test for {@link DecodeResponseHandler}. */
class DecodeResponseHandlerUnitTest {

    private HttpMessageHandlerContext ctx;
    private HttpResponseHeader responseHeader;
    private HttpResponseBody responseBody;
    private HttpMessage message;
    private HandlerState state;
    private DecodeResponseHandler handler;

    @BeforeEach
    void setUp() {
        ctx = mock(HttpMessageHandlerContext.class);
        responseBody = mock(HttpResponseBody.class);
        message = mock(HttpMessage.class);
        given(message.getResponseBody()).willReturn(responseBody);
        responseHeader = mock(HttpResponseHeader.class);
        given(message.getResponseHeader()).willReturn(responseHeader);
        state = mock(HandlerState.class);
        given(state.isEnabled()).willReturn(true);
        handler = new DecodeResponseHandler(state);
    }

    @Test
    void shouldNotHandleExcludedMessage() throws Exception {
        // Given
        given(ctx.isExcluded()).willReturn(true);
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(message, times(0)).getResponseBody();
    }

    @Test
    void shouldNotHandleRequest() throws Exception {
        // Given
        given(ctx.isFromClient()).willReturn(true);
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(message, times(0)).getResponseBody();
    }

    @Test
    void shouldNotDecodeResponseIfNotEncoded() throws Exception {
        // Given
        given(responseBody.getContentEncodings()).willReturn(Collections.emptyList());
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(responseBody, times(0)).setBody(any(byte[].class));
    }

    @Test
    void shouldNotDecodeResponseIfHasEncodingErrors() throws Exception {
        // Given
        given(responseBody.getContentEncodings())
                .willReturn(Arrays.asList(mock(HttpEncoding.class)));
        given(responseBody.hasContentEncodingErrors()).willReturn(true);
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(responseBody, times(0)).setBody(any(byte[].class));
    }

    @Test
    void shouldDecodeResponseWithResponseContent() throws Exception {
        // Given
        given(responseBody.getContentEncodings())
                .willReturn(Arrays.asList(mock(HttpEncoding.class)));
        byte[] content = {};
        given(responseBody.getContent()).willReturn(content);
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(responseBody).setBody(content);
    }

    @Test
    void shouldClearContentEncodingsInResponseAfterDecode() throws Exception {
        // Given
        given(responseBody.getContentEncodings())
                .willReturn(Arrays.asList(mock(HttpEncoding.class)));
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(responseBody).setContentEncodings(Collections.emptyList());
    }

    @Test
    void shouldRemoveContentEncodingHeaderAfterDecode() throws Exception {
        // Given
        given(responseBody.getContentEncodings())
                .willReturn(Arrays.asList(mock(HttpEncoding.class)));
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(responseHeader).setHeader(HttpHeader.CONTENT_ENCODING, null);
    }

    @Test
    void shouldUpdateContentLengthIfPresentAfterDecode() throws Exception {
        // Given
        given(responseBody.getContentEncodings())
                .willReturn(Arrays.asList(mock(HttpEncoding.class)));
        given(responseHeader.getHeader(HttpHeader.CONTENT_LENGTH)).willReturn("5");
        given(responseBody.length()).willReturn(10);
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(responseHeader).setContentLength(10);
    }

    @Test
    void shouldDecodeResponseWithAlwaysEnabledInstance() throws Exception {
        // Given
        given(responseBody.getContentEncodings())
                .willReturn(Arrays.asList(mock(HttpEncoding.class)));
        byte[] content = {};
        given(responseBody.getContent()).willReturn(content);
        handler = DecodeResponseHandler.getEnabledInstance();
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(responseBody).setBody(content);
    }

    @Test
    void shouldNotDecodeResponseIfDisabled() throws Exception {
        // Given
        given(responseBody.getContentEncodings())
                .willReturn(Arrays.asList(mock(HttpEncoding.class)));
        byte[] content = {};
        given(responseBody.getContent()).willReturn(content);
        given(state.isEnabled()).willReturn(false);
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(responseBody, times(0)).setBody(content);
    }
}
