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
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;

import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.network.HttpBody;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

/** Unit test for {@link HttpMessageDecoder}. */
abstract class HttpMessageDecoderUnitTest {

    protected static final int MAX_CHUNK_SIZE = HttpMessageDecoder.MAX_CHUNK_SIZE;

    protected EmbeddedChannel channel;

    @BeforeEach
    void setUp() {
        channel = new EmbeddedChannel(createDecoder());
    }

    protected abstract HttpMessageDecoder createDecoder();

    protected abstract HttpHeader extractHeader(HttpMessage message);

    protected abstract HttpBody extractBody(HttpMessage message);

    protected abstract String getPrimeHeader();

    protected abstract String getMalformedPrimeHeader();

    @Test
    void shouldNotProduceMessageWithNoInput() {
        // Given / When
        channel.close();
        // Then
        HttpMessage message = channel.readInbound();
        assertThat(message, is(nullValue()));
        assertChannelState();
    }

    @ParameterizedTest
    @MethodSource("unterminatedHeaders")
    void shouldProduceMessageWithExceptionForUnterminatedHeader(String content) {
        // Given
        written(content, false);
        // When
        channel.close();
        // Then
        HttpMessage message = channel.readInbound();
        assertThat(message, is(notNullValue()));
        assertThat(message.getUserObject(), is(instanceOf(HttpMalformedHeaderException.class)));
        assertChannelState();
    }

    @ParameterizedTest
    @MethodSource("invalidHeaders")
    void shouldProduceMessageWithExceptionForInvalidHeader(String content) {
        // Given /When
        written(content, true);
        // Then
        HttpMessage message = channel.readInbound();
        assertThat(message, is(notNullValue()));
        assertThat(message.getUserObject(), is(instanceOf(HttpMalformedHeaderException.class)));
        assertChannelState();
    }

    @ParameterizedTest
    @MethodSource("headersDifferentSeparators")
    void shouldReadHeaderWithDifferentSeparators(String content) {
        // Given / When
        written(content, true);
        // Then
        HttpMessage message = channel.readInbound();
        assertThat(message, is(notNullValue()));
        HttpHeader header = extractHeader(message);
        assertThat(header.getHeaders(), hasSize(2));
        checkHeader(header, 0, "Content-Length", "0");
        checkHeader(header, 1, "Y", "x");
        assertThat(extractBody(message).toString(), is(equalTo("")));
        assertChannelState();
    }

    @Test
    void shouldReadFixedLengthBody() {
        // Given
        String body = "0123456789012345";
        String content = getPrimeHeader() + "Content-Length: 16\r\n\r\n" + body;
        // When
        written(content, true);
        // Then
        HttpMessage message = channel.readInbound();
        assertThat(message, is(notNullValue()));
        HttpHeader header = extractHeader(message);
        assertThat(header.getHeaders(), hasSize(1));
        checkHeader(header, 0, "Content-Length", "16");
        assertThat(extractBody(message).toString(), is(equalTo(body)));
        assertChannelState();
    }

    @Test
    void shouldReadConsecutiveFixedLengthBodyMessages() {
        // Given
        int numberOfRequests = 2;
        String content =
                StringUtils.repeat(
                        getPrimeHeader() + "Content-Length: 1\r\n\r\nA", numberOfRequests);
        // When
        written(content, true);
        // Then
        for (int i = 0; i < numberOfRequests; i++) {
            HttpMessage message = channel.readInbound();
            assertThat(message, is(notNullValue()));
            HttpHeader header = extractHeader(message);
            checkHeader(header, 0, "Content-Length", "1");
            assertThat(extractBody(message).toString(), is(equalTo("A")));
        }
        assertChannelState();
    }

    @Test
    void shouldProduceMessageWithExceptionIfChannelClosedBeforeSendingFullFixedLengthBody() {
        // Given / When
        written(getPrimeHeader() + "Content-Length: 5\r\n\r\n123", false);
        channel.close();
        // Then
        HttpMessage message = channel.readInbound();
        assertThat(message, is(notNullValue()));
        assertThat(message.getUserObject(), is(instanceOf(HttpMalformedHeaderException.class)));
        assertThat(extractBody(message).toString(), is(equalTo("123")));
        assertChannelState();
    }

    @Test
    void shouldReadBodyUsingLastContentLengthHeader() {
        // Given
        String body = "0123456789012345";
        String content =
                getPrimeHeader() + "Content-Length: 4\r\nContent-Length: 16\r\n\r\n" + body;
        // When
        written(content, true);
        // Then
        HttpMessage message = channel.readInbound();
        assertThat(message, is(notNullValue()));
        HttpHeader header = extractHeader(message);
        assertThat(header.getHeaders(), hasSize(2));
        checkHeader(header, 0, "Content-Length", "4", "16");
        assertThat(extractBody(message).toString(), is(equalTo(body)));
        assertChannelState();
    }

    @ParameterizedTest
    @ValueSource(strings = {"3\r\nAbc\r\n4\r\nwxyz\r\n0\r\n\r\n", "7\nAbcwxyz\n0\n\n"})
    void shouldReadChunkedBody(String chunkedBody) {
        // Given
        String content = getPrimeHeader() + "Transfer-Encoding: chunked\r\n\r\n" + chunkedBody;
        // When
        written(content, true);
        // Then
        HttpMessage message = channel.readInbound();
        assertThat(message, is(notNullValue()));
        HttpHeader header = extractHeader(message);
        assertThat(header.getHeaders(), hasSize(1));
        checkHeader(header, 0, "Content-Length", "7");
        assertThat(extractBody(message).toString(), is(equalTo("Abcwxyz")));
        assertChannelState();
    }

    @Test
    void shouldReadChunkedBodyIgnoringAndUpdatingExistingContentLength() {
        // Given
        String content =
                getPrimeHeader()
                        + "Content-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nAbc\r\n4\r\nwxyz\r\n0\r\n\r\n";
        // When
        written(content, true);
        // Then
        HttpMessage message = channel.readInbound();
        assertThat(message, is(notNullValue()));
        HttpHeader header = extractHeader(message);
        assertThat(header.getHeaders(), hasSize(1));
        checkHeader(header, 0, "Content-Length", "7");
        assertThat(extractBody(message).toString(), is(equalTo("Abcwxyz")));
        assertChannelState();
    }

    @ParameterizedTest
    @ValueSource(strings = {" ", ";", " ;", "\b ;"})
    void shouldReadChunkedBodySizeWithSurroundingChars(String chunkSizeChars) {
        // Given
        String content =
                getPrimeHeader()
                        + "Transfer-Encoding: chunked\r\n\r\n 3"
                        + chunkSizeChars
                        + "\r\nAbc\r\n0\r\n\r\n";
        // When
        written(content, true);
        // Then
        HttpMessage message = channel.readInbound();
        assertThat(message, is(notNullValue()));
        HttpHeader header = extractHeader(message);
        assertThat(header.getHeaders(), hasSize(1));
        checkHeader(header, 0, "Content-Length", "3");
        assertThat(extractBody(message).toString(), is(equalTo("Abc")));
        assertChannelState();
    }

    @Test
    void shouldProduceMessageWithExceptionIfChannelClosedBeforeSendingFullChunkedBody() {
        // Given / When
        written(getPrimeHeader() + "Transfer-Encoding: chunked\r\n\r\n3\r\nAbc\r\n", false);
        channel.close();
        // Then
        HttpMessage message = channel.readInbound();
        assertThat(message, is(notNullValue()));
        assertThat(message.getUserObject(), is(instanceOf(HttpMalformedHeaderException.class)));
        assertThat(extractBody(message).toString(), is(equalTo("Abc")));
        assertChannelState();
    }

    @Test
    void shouldReadChunkedBodyIgnoringOtherTransferEncodings() {
        // Given
        String content =
                getPrimeHeader()
                        + "Transfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nAbc\r\n4\r\nwxyz\r\n0\r\n\r\n";
        written(content, true);
        // When
        HttpMessage message = channel.readInbound();
        // Then
        assertThat(message, is(notNullValue()));
        HttpHeader header = extractHeader(message);
        assertThat(header.getHeaders(), hasSize(1));
        checkHeader(header, 0, "Content-Length", "7");
        assertThat(extractBody(message).toString(), is(equalTo("Abcwxyz")));
        assertChannelState();
    }

    @ParameterizedTest
    @ValueSource(strings = {"-\r\n", "-1\r\n", "G\r\n"})
    void shouldProduceMessageWithExceptionForInvalidChunkSize(String chunkedBody) {
        // Given
        String content = getPrimeHeader() + "Transfer-Encoding: chunked\r\n\r\n" + chunkedBody;
        // When
        written(content, true);
        // Then
        HttpMessage message = channel.readInbound();
        assertThat(message, is(notNullValue()));
        assertThat(message.getUserObject(), is(instanceOf(Exception.class)));
        assertChannelState();
    }

    @Test
    void shouldReadTrailingHeaders() {
        // Given
        String content =
                getPrimeHeader() + "Transfer-Encoding: chunked\r\n\r\n0\r\nA: b\r\nX: y\r\n\r\n";
        // When
        written(content, true);
        // Then
        HttpMessage message = channel.readInbound();
        assertThat(message, is(notNullValue()));
        HttpHeader header = extractHeader(message);
        assertThat(header.getHeaders(), hasSize(3));
        checkHeader(header, 0, "A", "b");
        checkHeader(header, 1, "X", "y");
        checkHeader(header, 2, "Content-Length", "0");
        assertThat(extractBody(message).toString(), is(equalTo("")));
        assertChannelState();
    }

    @ParameterizedTest
    @ValueSource(ints = {1, MAX_CHUNK_SIZE - 1, MAX_CHUNK_SIZE, MAX_CHUNK_SIZE + 1})
    void shouldReadChunkedBodyIncrementally(int batchSize) {
        // Given
        String body = StringUtils.repeat("A", batchSize);
        String chunkLength = Integer.toHexString(batchSize);
        String chunkedBody = chunkLength + "\r\n" + body + "\r\n0\r\nA: b\r\nX: y\r\n\r\n";
        written(getPrimeHeader() + "Transfer-Encoding: chunked\r\n\r\n", false);
        // When
        writtenIncrementally(chunkedBody, batchSize);
        // Then
        HttpMessage message = channel.readInbound();
        assertThat(message, is(notNullValue()));
        assertThat(extractBody(message).toString(), is(equalTo(body)));
        assertChannelState();
    }

    @ParameterizedTest
    @ValueSource(strings = {"X\n", "X y"})
    void shouldProduceMessageWithExceptionForInvalidTrailingHeader(String header) {
        // Given
        String content =
                getPrimeHeader() + "Transfer-Encoding: chunked\r\n\r\n0\r\n" + header + "\r\n\r\n";
        // When
        written(content, true);
        // Then
        HttpMessage message = channel.readInbound();
        assertThat(message, is(notNullValue()));
        assertThat(message.getUserObject(), is(instanceOf(HttpMalformedHeaderException.class)));
        assertChannelState();
    }

    @Test
    void shouldConsumeAllInputAfterBadMessage() {
        // Given
        written(getMalformedPrimeHeader() + "\r\n", true);
        channel.readInbound();
        // When / Then
        written(getPrimeHeader() + "\r\n", false);
        assertChannelState();
    }

    @Test
    void shouldSetContentEncodings() {
        // Given
        String content = getPrimeHeader() + "Content-Encoding: gzip\r\nContent-Length: 1\r\n\r\nA";
        // When
        written(content, true);
        // Then
        HttpMessage message = channel.readInbound();
        assertThat(message, is(notNullValue()));
        assertThat(extractBody(message).getContentEncodings(), is(not(empty())));
        assertChannelState();
    }

    @Test
    void shouldNotSetContentEncodingsIfNone() {
        // Given
        String content = getPrimeHeader() + "Content-Length: 1\r\n\r\nA";
        // When
        written(content, true);
        // Then
        HttpMessage message = channel.readInbound();
        assertThat(message, is(notNullValue()));
        assertThat(extractBody(message).getContentEncodings(), is(empty()));
        assertChannelState();
    }

    protected void assertChannelState() {
        assertThat(channel.finish(), is(equalTo(false)));
        assertThat(channel.readInbound(), is(nullValue()));
    }

    protected void writtenIncrementally(String request, int amount) {
        for (int i = 0, len = request.length(); i < len; ) {
            int nextPos = Math.min(i + amount, len);
            written(request.substring(i, nextPos), nextPos == len);
            i = nextPos;
        }
    }

    protected void written(String content, boolean written) {
        byte[] bytes = content.getBytes(StandardCharsets.US_ASCII);
        assertThat(channel.writeInbound(Unpooled.copiedBuffer(bytes)), is(equalTo(written)));
    }

    protected static void checkHeader(HttpHeader header, int pos, String name, String... value) {
        List<String> headerValues = header.getHeaderValues(name);
        assertThat(headerValues, contains(value));
        HttpHeaderField headerField = header.getHeaders().get(pos);
        assertThat(headerField.getName(), is(equalTo(name)));
        assertThat(headerField.getValue(), is(equalTo(value[0])));
    }
}
