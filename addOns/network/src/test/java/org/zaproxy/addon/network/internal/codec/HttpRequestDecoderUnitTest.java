/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.network.internal.codec;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;

import java.net.InetSocketAddress;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.network.HttpBody;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.network.internal.ChannelAttributes;

/** Unit test for {@link HttpRequestDecoder}. */
class HttpRequestDecoderUnitTest extends HttpMessageDecoderUnitTest {

    private static final InetSocketAddress SENDER_ADDRESS =
            new InetSocketAddress("127.0.0.1", 1234);

    @BeforeEach
    void setUpAttributes() {
        channel.attr(ChannelAttributes.REMOTE_ADDRESS).set(SENDER_ADDRESS);
        channel.attr(ChannelAttributes.TLS_UPGRADED).set(Boolean.FALSE);
    }

    @Override
    protected HttpRequestDecoder createDecoder() {
        return new HttpRequestDecoder();
    }

    @Override
    protected HttpHeader extractHeader(HttpMessage message) {
        return message.getRequestHeader();
    }

    @Override
    protected HttpBody extractBody(HttpMessage message) {
        return message.getRequestBody();
    }

    @Override
    protected String getPrimeHeader() {
        return "POST / HTTP/1.1\r\n";
    }

    @Override
    protected String getMalformedPrimeHeader() {
        return "GET / \r\n";
    }

    static Stream<String> unterminatedHeaders() {
        return Stream.of(
                "\n",
                "\r\n",
                "GET / HTTP/1.1\r\r\n",
                "GET",
                "GET /",
                "GET / HTTP/1.1",
                "GET / HTTP/1.1\r\n",
                "GET / HTTP/1.1\r\nX: y\r\n",
                "GET / HTTP/1.1\nX: y\n");
    }

    static Stream<String> invalidHeaders() {
        return Stream.of(
                "GET\r\n\r\nMore Data",
                "GET /\r\n\r\nMore Data",
                "GET / HTTP/\r\n\r\nMore Data",
                "GET / HTTP/\n\nMore Data");
    }

    static Stream<String> headersDifferentSeparators() {
        return Stream.of(
                "GET / HTTP/1.1\r\nContent-Length: 0\r\nY: x\r\n\r\n",
                "GET / HTTP/1.1\nContent-Length: 0\nY: x\n\n",
                "GET / HTTP/1.1\nContent-Length: 0\r\nY: x\r\n\n");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "\r\nContent-Length: 0"})
    void shouldReadEmptyBody(String contentLength) {
        // Given
        String content = "POST / HTTP/1.1" + contentLength + "\r\n\r\n";
        // When
        written(content, true);
        // Then
        HttpMessage message = channel.readInbound();
        assertThat(message, is(notNullValue()));
        assertThat(extractBody(message).toString(), is(equalTo("")));
        assertChannelState();
    }

    @Test
    void shouldBeSecureIfTlsUpgraded() {
        // Given
        channel.attr(ChannelAttributes.TLS_UPGRADED).set(Boolean.TRUE);
        String content = "GET / HTTP/1.1\r\n\r\n";
        // When
        written(content, true);
        // Then
        HttpMessage message = channel.readInbound();
        assertThat(message, is(notNullValue()));
        assertThat(message.getRequestHeader().isSecure(), is(equalTo(true)));
        assertChannelState();
    }

    @Test
    void shouldNotBeSecureIfNotTlsUpgraded() {
        // Given
        channel.attr(ChannelAttributes.TLS_UPGRADED).set(Boolean.FALSE);
        String content = "GET / HTTP/1.1\r\n\r\n";
        // When
        written(content, true);
        // Then
        HttpMessage message = channel.readInbound();
        assertThat(message, is(notNullValue()));
        assertThat(message.getRequestHeader().isSecure(), is(equalTo(false)));
        assertChannelState();
    }

    @Test
    void shouldProduceMessageWithExceptionForNullTlsUpgraded() {
        // Given
        channel.attr(ChannelAttributes.TLS_UPGRADED).set(null);
        String content = "GET / HTTP/1.1\r\n\r\n";
        // When
        written(content, true);
        // Then
        HttpMessage message = channel.readInbound();
        assertThat(message, is(notNullValue()));
        assertThat(message.getUserObject(), is(instanceOf(NullPointerException.class)));
        assertChannelState();
    }

    @Test
    void shouldHaveSenderAddress() {
        // Given
        InetSocketAddress senderAddress = new InetSocketAddress("127.0.0.3", 1234);
        channel.attr(ChannelAttributes.REMOTE_ADDRESS).set(senderAddress);
        String content = "GET / HTTP/1.1\r\n\r\n";
        // When
        written(content, true);
        // Then
        HttpMessage message = channel.readInbound();
        assertThat(message, is(notNullValue()));
        assertThat(
                message.getRequestHeader().getSenderAddress(),
                is(equalTo(senderAddress.getAddress())));
        assertChannelState();
    }

    @Test
    void shouldProduceMessageWithExceptionForNullRemoteAddress() {
        // Given
        channel.attr(ChannelAttributes.REMOTE_ADDRESS).set(null);
        String content = "GET / HTTP/1.1\r\n\r\n";
        // When
        written(content, true);
        // Then
        HttpMessage message = channel.readInbound();
        assertThat(message, is(notNullValue()));
        assertThat(message.getUserObject(), is(instanceOf(NullPointerException.class)));
        assertChannelState();
    }
}
