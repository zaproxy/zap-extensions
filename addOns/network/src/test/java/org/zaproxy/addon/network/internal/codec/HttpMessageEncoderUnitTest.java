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
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import io.netty.buffer.ByteBuf;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.EncoderException;
import java.nio.charset.StandardCharsets;
import java.util.function.Function;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpBody;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;

/** Unit test for {@link HttpMessageEncoder}. */
class HttpMessageEncoderUnitTest {

    private HttpHeader header;
    private HttpBody body;
    private HttpMessageEncoder encoder;
    private EmbeddedChannel channel;

    @BeforeEach
    void setUp() {
        header = mock(HttpHeader.class);
        given(header.getPrimeHeader()).willReturn("Prime Header");
        given(header.getHeadersAsString()).willReturn("Headers");
        body = mock(HttpBody.class);
        encoder = new HttpMessageEncoderImpl(msg -> header, msg -> body);
        channel = new EmbeddedChannel(encoder);
    }

    @Test
    void shouldBeSharable() {
        assertThat(encoder.isSharable(), is(equalTo(true)));
    }

    @Test
    void shouldEncodeHeaderAndBodyInHttpMessage() throws Exception {
        // Given
        HttpMessage httpMessage = new HttpMessage();
        given(body.length()).willReturn(4);
        given(body.getBytes()).willReturn("Body".getBytes(StandardCharsets.US_ASCII));
        // When
        boolean written = channel.writeOutbound(httpMessage);
        // Then
        assertThat(written, is(equalTo(true)));
        ByteBuf encoded = channel.readOutbound();
        assertNotNull(encoded);
        assertThat(
                encoded.toString(StandardCharsets.US_ASCII),
                is(equalTo("Prime Header\r\nHeaders\r\nBody")));
        encoded.release();
        assertChannelStateEnd();
    }

    @Test
    void shouldEncodeNonAsciiHeaderInHttpMessage() throws Exception {
        // Given
        HttpMessage httpMessage = new HttpMessage();
        given(header.getPrimeHeader()).willReturn("Prime J/ψ:  → VP Header");
        given(header.getHeadersAsString()).willReturn("Headers J/ψ:  → VP");
        // When
        boolean written = channel.writeOutbound(httpMessage);
        // Then
        assertThat(written, is(equalTo(true)));
        ByteBuf encoded = channel.readOutbound();
        assertNotNull(encoded);
        assertThat(
                encoded.toString(StandardCharsets.UTF_8),
                is(equalTo("Prime J/ψ:  → VP Header\r\nHeaders J/ψ:  → VP\r\n")));
        encoded.release();
        assertChannelStateEnd();
    }

    @Test
    void shouldNotGetBodyBytesIfBodyEmpty() throws Exception {
        // Given
        HttpMessage httpMessage = new HttpMessage();
        given(body.length()).willReturn(0);
        // When
        boolean written = channel.writeOutbound(httpMessage);
        // Then
        assertThat(written, is(equalTo(true)));
        ByteBuf encoded = channel.readOutbound();
        assertNotNull(encoded);
        assertThat(
                encoded.toString(StandardCharsets.US_ASCII),
                is(equalTo("Prime Header\r\nHeaders\r\n")));
        encoded.release();
        assertChannelStateEnd();
        verify(body, times(0)).getBytes();
    }

    @Test
    void shouldThrowExceptionIfEncodingNullHeader() {
        // Given
        encoder = new HttpMessageEncoderImpl(msg -> null, msg -> body);
        channel = new EmbeddedChannel(encoder);
        // When / Then
        EncoderException exception =
                assertThrows(
                        EncoderException.class, () -> channel.writeOutbound(new HttpMessage()));
        assertThat(exception.getCause(), is(instanceOf(NullPointerException.class)));
    }

    @Test
    void shouldThrowExceptionIfEncodingNullBody() {
        // Given
        encoder = new HttpMessageEncoderImpl(msg -> header, msg -> null);
        channel = new EmbeddedChannel(encoder);
        // When / Then
        EncoderException exception =
                assertThrows(
                        EncoderException.class, () -> channel.writeOutbound(new HttpMessage()));
        assertThat(exception.getCause(), is(instanceOf(NullPointerException.class)));
    }

    private void assertChannelStateEnd() {
        assertFalse(channel.finish());
        assertNull(channel.readInbound());
    }

    private static class HttpMessageEncoderImpl extends HttpMessageEncoder {

        HttpMessageEncoderImpl(
                Function<HttpMessage, HttpHeader> headerProvider,
                Function<HttpMessage, HttpBody> bodyProvider) {
            super(headerProvider, bodyProvider);
        }
    }
}
