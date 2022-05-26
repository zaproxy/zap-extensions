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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

/** Unit test for {@link CloseOnRecursiveRequestHandler}. */
class CloseOnRecursiveRequestHandlerUnitTest {

    private HttpMessageHandlerContext ctx;
    private HttpMessage message;
    private CloseOnRecursiveRequestHandler handler;

    @BeforeEach
    void setUp() {
        ctx = mock(HttpMessageHandlerContext.class);
        given(ctx.isFromClient()).willReturn(true);
        message = mock(HttpMessage.class);
        handler = CloseOnRecursiveRequestHandler.getInstance();
    }

    @Test
    void shouldCloseRecursiveExcludedMessage() throws Exception {
        // Given
        given(ctx.isRecursive()).willReturn(true);
        given(ctx.isExcluded()).willReturn(true);
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(ctx).close();
    }

    @Test
    void shouldNotHandleResponse() throws Exception {
        // Given
        given(ctx.isRecursive()).willReturn(true);
        given(ctx.isFromClient()).willReturn(false);
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(ctx, times(0)).close();
    }

    @Test
    void shouldNotCloseIfNotRecursive() throws Exception {
        // Given
        given(ctx.isRecursive()).willReturn(false);
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(ctx, times(0)).close();
    }

    @Test
    void shouldCloseIfRecursiveRequest() throws Exception {
        // Given
        given(ctx.isRecursive()).willReturn(true);
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(ctx).close();
    }
}
