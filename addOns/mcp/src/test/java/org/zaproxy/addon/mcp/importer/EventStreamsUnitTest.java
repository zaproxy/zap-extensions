/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.mcp.importer;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.sameInstance;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;

/** Unit tests for {@link EventStreams}. */
@SuppressWarnings("deprecation")
class EventStreamsUnitTest {

    private static final String SSE_BODY =
            "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n\n";

    @Test
    void shouldReturnEmptyInputStreamWhenUserObjectIsNotZapGetMethod() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setUserObject("not a ZapGetMethod");
        // When
        Optional<InputStream> stream = EventStreams.getInputStream(msg);
        // Then
        assertThat(stream.isEmpty(), is(true));
    }

    @Test
    void shouldReturnEmptySocketWhenUserObjectIsNotZapGetMethod() {
        // Given
        HttpMessage msg = new HttpMessage();
        // When / Then
        assertThat(EventStreams.getSocket(msg).isEmpty(), is(true));
    }

    @Test
    void shouldReturnInputStreamFromZapGetMethod() throws Exception {
        // Given
        InputStream attached = new ByteArrayInputStream(new byte[0]);
        org.zaproxy.zap.ZapGetMethod method = mock(org.zaproxy.zap.ZapGetMethod.class);
        given(method.getResponseBodyAsStream()).willReturn(attached);
        HttpMessage msg = new HttpMessage();
        msg.setUserObject(method);
        // When
        Optional<InputStream> stream = EventStreams.getInputStream(msg);
        // Then
        assertThat(stream.isPresent(), is(true));
        assertThat(stream.get(), is(sameInstance(attached)));
    }

    @Test
    void shouldReturnSocketFromZapGetMethod() {
        // Given
        Socket socket = mock(Socket.class);
        org.zaproxy.zap.ZapGetMethod method = mock(org.zaproxy.zap.ZapGetMethod.class);
        given(method.getUpgradedConnection()).willReturn(socket);
        HttpMessage msg = new HttpMessage();
        msg.setUserObject(method);
        // When / Then
        assertThat(EventStreams.getSocket(msg).orElse(null), is(sameInstance(socket)));
    }

    @Test
    void shouldReturnFalseFromConsumeBodyWhenNoStreamAttached() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        // When / Then
        assertThat(EventStreams.consumeBody(msg), is(false));
    }

    @Test
    void shouldDrainStreamIntoBodyAndCloseSocketOnConsumeBody() throws Exception {
        // Given
        InputStream stream = new ByteArrayInputStream(SSE_BODY.getBytes(StandardCharsets.UTF_8));
        Socket socket = mock(Socket.class);
        org.zaproxy.zap.ZapGetMethod method = mock(org.zaproxy.zap.ZapGetMethod.class);
        given(method.getResponseBodyAsStream()).willReturn(stream);
        given(method.getUpgradedConnection()).willReturn(socket);
        HttpMessage msg = new HttpMessage();
        msg.setUserObject(method);
        // When
        boolean consumed = EventStreams.consumeBody(msg);
        // Then
        assertThat(consumed, is(true));
        assertThat(msg.getResponseBody().toString(), is(equalTo(SSE_BODY)));
        assertThat(
                msg.getResponseHeader().getContentLength(),
                is(equalTo(SSE_BODY.getBytes(StandardCharsets.UTF_8).length)));
        verify(socket).close();
    }

    @Test
    void shouldReadOnlyContentLengthBytesWhenHeaderIsPresent() throws Exception {
        // Given - stream has trailing bytes that must NOT be read or the call would block on a
        // keep-alive connection.
        byte[] bodyBytes = SSE_BODY.getBytes(StandardCharsets.UTF_8);
        InputStream stream =
                new ByteArrayInputStream(
                        (SSE_BODY + "extra-bytes-that-should-not-be-read")
                                .getBytes(StandardCharsets.UTF_8));
        Socket socket = mock(Socket.class);
        org.zaproxy.zap.ZapGetMethod method = mock(org.zaproxy.zap.ZapGetMethod.class);
        given(method.getResponseBodyAsStream()).willReturn(stream);
        given(method.getUpgradedConnection()).willReturn(socket);
        HttpMessage msg = new HttpMessage();
        msg.setUserObject(method);
        msg.getResponseHeader().setContentLength(bodyBytes.length);
        // When
        boolean consumed = EventStreams.consumeBody(msg);
        // Then
        assertThat(consumed, is(true));
        assertThat(msg.getResponseBody().toString(), is(equalTo(SSE_BODY)));
        assertThat(msg.getResponseHeader().getContentLength(), is(equalTo(bodyBytes.length)));
        verify(socket).close();
    }

    @Test
    void shouldStopAtEofWhenContentLengthExceedsAvailableBytes() throws Exception {
        // Given - declared Content-Length is larger than the stream actually delivers.
        byte[] bodyBytes = SSE_BODY.getBytes(StandardCharsets.UTF_8);
        InputStream stream = new ByteArrayInputStream(bodyBytes);
        Socket socket = mock(Socket.class);
        org.zaproxy.zap.ZapGetMethod method = mock(org.zaproxy.zap.ZapGetMethod.class);
        given(method.getResponseBodyAsStream()).willReturn(stream);
        given(method.getUpgradedConnection()).willReturn(socket);
        HttpMessage msg = new HttpMessage();
        msg.setUserObject(method);
        msg.getResponseHeader().setContentLength(bodyBytes.length + 100);
        // When
        boolean consumed = EventStreams.consumeBody(msg);
        // Then
        assertThat(consumed, is(true));
        assertThat(msg.getResponseBody().toString(), is(equalTo(SSE_BODY)));
        assertThat(msg.getResponseHeader().getContentLength(), is(equalTo(bodyBytes.length)));
        verify(socket).close();
    }

    @Test
    void shouldStillCloseSocketWhenStreamReadFails() throws Exception {
        // Given
        InputStream failing =
                new InputStream() {
                    @Override
                    public int read() throws java.io.IOException {
                        throw new java.io.IOException("boom");
                    }
                };
        Socket socket = mock(Socket.class);
        org.zaproxy.zap.ZapGetMethod method = mock(org.zaproxy.zap.ZapGetMethod.class);
        given(method.getResponseBodyAsStream()).willReturn(failing);
        given(method.getUpgradedConnection()).willReturn(socket);
        HttpMessage msg = new HttpMessage();
        msg.setUserObject(method);
        // When
        try {
            EventStreams.consumeBody(msg);
        } catch (java.io.IOException expected) {
            // Then
        }
        verify(socket).close();
    }

    @Test
    void shouldNotTouchSocketWhenConsumeBodyIsANoOp() throws Exception {
        // Given - ZapGetMethod attached with a socket but no stream, so consumeBody bails early.
        Socket socket = mock(Socket.class);
        org.zaproxy.zap.ZapGetMethod method = mock(org.zaproxy.zap.ZapGetMethod.class);
        given(method.getResponseBodyAsStream()).willReturn(null);
        given(method.getUpgradedConnection()).willReturn(socket);
        HttpMessage msg = new HttpMessage();
        msg.setUserObject(method);
        // When
        boolean consumed = EventStreams.consumeBody(msg);
        // Then
        assertThat(consumed, is(false));
        verify(socket, never()).close();
    }
}
