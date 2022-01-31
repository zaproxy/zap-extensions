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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.sameInstance;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

/** Unit test for {@link HttpRequestHandler}. */
class HttpRequestHandlerUnitTest {

    private HttpMessageHandlerContext ctx;
    private HttpMessage message;
    private HttpRequestHandlerImpl handler;

    @BeforeEach
    void setUp() {
        ctx = mock(HttpMessageHandlerContext.class);
        message = mock(HttpMessage.class);
        handler = new HttpRequestHandlerImpl();
    }

    @Test
    void shouldNotHandleResponse() throws Exception {
        // Given
        given(ctx.isFromClient()).willReturn(false);
        // When
        handler.handleMessage(ctx, message);
        // Then
        assertThat(handler.isCalled(), is(equalTo(false)));
    }

    @Test
    void shouldHandleRequest() throws Exception {
        // Given
        given(ctx.isFromClient()).willReturn(true);
        // When
        handler.handleMessage(ctx, message);
        // Then
        assertThat(handler.isCalled(), is(equalTo(true)));
        assertThat(handler.ctx(), is(sameInstance(ctx)));
        assertThat(handler.msg(), is(sameInstance(message)));
    }

    private static class HttpRequestHandlerImpl extends HttpRequestHandler {

        private boolean called;
        private HttpMessageHandlerContext ctx;
        private HttpMessage msg;

        @Override
        protected void handleRequest(HttpMessageHandlerContext ctx, HttpMessage msg) {
            called = true;
            this.ctx = ctx;
            this.msg = msg;
        }

        boolean isCalled() {
            return called;
        }

        public HttpMessageHandlerContext ctx() {
            return ctx;
        }

        public HttpMessage msg() {
            return msg;
        }
    }
}
