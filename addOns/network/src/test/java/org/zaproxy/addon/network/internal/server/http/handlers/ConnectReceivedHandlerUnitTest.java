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
import static org.mockito.Mockito.anyLong;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

/** Unit test for {@link ConnectReceivedHandler}. */
class ConnectReceivedHandlerUnitTest {

    private static final String CONNECT_HTTP_200 = "HTTP/1.1 200 Connection established";

    private HttpMessageHandlerContext ctx;
    private HttpRequestHeader requestHeader;
    private HttpMessage message;
    private ConnectReceivedHandler handler;

    @BeforeEach
    void setUp() {
        ctx = mock(HttpMessageHandlerContext.class);
        given(ctx.isFromClient()).willReturn(true);
        requestHeader = mock(HttpRequestHeader.class);
        given(requestHeader.getMethod()).willReturn(HttpRequestHeader.GET);
        message = mock(HttpMessage.class);
        given(message.getRequestHeader()).willReturn(requestHeader);
    }

    @Test
    void shouldNotSetNorOverrideForNonConnect() throws Exception {
        // Given
        given(requestHeader.getMethod()).willReturn(HttpRequestHeader.GET);
        handler = ConnectReceivedHandler.getSetAndOverrideInstance();
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(message, times(0)).setTimeSentMillis(anyLong());
        verify(message, times(0)).setResponseHeader(anyString());
        assertContext(0, 0);
    }

    @Test
    void shouldNotSetNorOverrideForConnectResponse() throws Exception {
        // Given
        given(requestHeader.getMethod()).willReturn(HttpRequestHeader.CONNECT);
        given(ctx.isFromClient()).willReturn(false);
        handler = ConnectReceivedHandler.getSetAndOverrideInstance();
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(message, times(0)).setTimeSentMillis(anyLong());
        verify(message, times(0)).setResponseHeader(anyString());
        assertContext(0, 0);
    }

    @Test
    void shouldSetNorOverrideForConnectRequest() throws Exception {
        // Given
        given(requestHeader.getMethod()).willReturn(HttpRequestHeader.CONNECT);
        handler = ConnectReceivedHandler.getSetAndOverrideInstance();
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(message, times(1)).setTimeSentMillis(anyLong());
        verify(message, times(1)).setResponseHeader(CONNECT_HTTP_200);
        assertContext(1, 0);
    }

    @Test
    void shouldNotSetButContinueForNonConnect() throws Exception {
        // Given
        given(requestHeader.getMethod()).willReturn(HttpRequestHeader.GET);
        handler = ConnectReceivedHandler.getSetAndContinueInstance();
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(message, times(0)).setTimeSentMillis(anyLong());
        verify(message, times(0)).setResponseHeader(anyString());
        assertContext(0, 0);
    }

    @Test
    void shouldNotSetButContinueForConnectResponse() throws Exception {
        // Given
        given(requestHeader.getMethod()).willReturn(HttpRequestHeader.CONNECT);
        given(ctx.isFromClient()).willReturn(false);
        handler = ConnectReceivedHandler.getSetAndContinueInstance();
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(message, times(0)).setTimeSentMillis(anyLong());
        verify(message, times(0)).setResponseHeader(anyString());
        assertContext(0, 0);
    }

    @Test
    void shouldSetAndContinueForConnectRequest() throws Exception {
        // Given
        given(requestHeader.getMethod()).willReturn(HttpRequestHeader.CONNECT);
        handler = ConnectReceivedHandler.getSetAndContinueInstance();
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(message, times(1)).setTimeSentMillis(anyLong());
        verify(message, times(1)).setResponseHeader(CONNECT_HTTP_200);
        assertContext(0, 0);
    }

    private void assertContext(int overridden, int closed) {
        verify(ctx, times(overridden)).overridden();
        verify(ctx, times(closed)).close();
    }
}
