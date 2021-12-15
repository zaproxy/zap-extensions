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
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;

import io.netty.buffer.ByteBuf;
import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.network.HttpBody;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;

/** Unit test for {@link HttpResponseDecoder}. */
class HttpResponseDecoderUnitTest extends HttpMessageDecoderUnitTest {

    @Override
    protected HttpResponseDecoder createDecoder() {
        return new HttpResponseDecoder();
    }

    @Override
    protected HttpHeader extractHeader(HttpMessage message) {
        return message.getResponseHeader();
    }

    @Override
    protected HttpBody extractBody(HttpMessage message) {
        return message.getResponseBody();
    }

    @Override
    protected String getPrimeHeader() {
        return "HTTP/1.1 200 OK\r\n";
    }

    @Override
    protected String getMalformedPrimeHeader() {
        return "HTTP \r\n";
    }

    static Stream<String> unterminatedHeaders() {
        return Stream.of(
                "\n",
                "\r\n",
                "HTTP/1.1 200 OK\r\r\n",
                "HTTP",
                "HTTP/",
                "HTTP/1.1 200 OK",
                "HTTP/1.1 200 OK\r\n",
                "HTTP/1.1 200 OK\r\nX: y\r\n",
                "HTTP/1.1 200 OK\nX: y\n");
    }

    static Stream<String> invalidHeaders() {
        return Stream.of("HTTP\r\n\r\nMore Data", "HTTP/\r\n\r\nMore Data");
    }

    static Stream<String> headersDifferentSeparators() {
        return Stream.of(
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nY: x\r\n\r\n",
                "HTTP/1.1 200 OK\nContent-Length: 0\nY: x\n\n",
                "HTTP/1.1 200 OK\nContent-Length: 0\r\nY: x\r\n\n");
    }

    @Test
    void shouldReadBodyToConnectionEnd() {
        // Given
        String content = "HTTP/1.1 200 OK\r\n\r\nABC";
        // When
        written(content, false);
        channel.close();
        // Then
        HttpMessage message = channel.readInbound();
        assertThat(message, is(notNullValue()));
        assertThat(extractBody(message).toString(), is(equalTo("ABC")));
        assertChannelState();
    }

    @ParameterizedTest
    @ValueSource(ints = {100, 101, 150, 199, 204, 304})
    void shouldNotReadContentAsBodyIfNoneExpected(int statusCode) {
        // Given
        String content =
                "HTTP/1.1 "
                        + statusCode
                        + "\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nABC";
        // When
        written(content, true);
        // Then
        HttpMessage message = channel.readInbound();
        assertThat(message, is(notNullValue()));
        assertThat(extractBody(message).toString(), is(equalTo("")));
        message = channel.readInbound();
        assertThat(message, is(notNullValue()));
        assertThat(extractBody(message).toString(), is(equalTo("ABC")));
        assertChannelState();
    }

    @Test
    void shouldNotConsumeContentAsHttpAfterNonHttp1Upgrade() {
        // Given
        String content = "HTTP/1.1 101\r\nUpgrade: websocket\r\n\r\nHTTP/1.1 200 OK\r\n\r\n";
        // When
        written(content, true);
        // Then
        HttpMessage message = channel.readInbound();
        assertThat(message, is(notNullValue()));
        assertThat(extractBody(message).toString(), is(equalTo("")));
        ByteBuf data = channel.readInbound();
        assertThat(data, is(notNullValue()));
        assertThat(
                data.toString(StandardCharsets.US_ASCII), is(equalTo("HTTP/1.1 200 OK\r\n\r\n")));
        assertChannelState();
    }

    @ParameterizedTest
    @ValueSource(strings = {HttpHeader.HTTP10, HttpHeader.HTTP11})
    void shouldConsumeContentAsHttpAfterHttp1Upgrade(String httpVersion) {
        // Given
        String content =
                "HTTP/1.1 101\r\nUpgrade: "
                        + httpVersion
                        + "\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nABC";
        // When
        written(content, true);
        // Then
        HttpMessage message = channel.readInbound();
        assertThat(message, is(notNullValue()));
        assertThat(extractBody(message).toString(), is(equalTo("")));
        message = channel.readInbound();
        assertThat(message, is(notNullValue()));
        assertThat(extractBody(message).toString(), is(equalTo("ABC")));
        assertChannelState();
    }
}
