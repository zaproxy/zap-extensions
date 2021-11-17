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
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

import io.netty.buffer.ByteBuf;
import io.netty.channel.embedded.EmbeddedChannel;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.network.HttpResponseBody;

/** Unit test for {@link HttpResponseEncoder}. */
class HttpResponseEncoderUnitTest {

    private EmbeddedChannel channel;

    @BeforeEach
    void setUp() {
        channel = new EmbeddedChannel(HttpResponseEncoder.getInstance());
    }

    @Test
    void shouldBeSharable() {
        assertThat(HttpResponseEncoder.getInstance().isSharable(), is(equalTo(true)));
    }

    @Test
    void shouldEncodeResponseInHttpMessage() throws Exception {
        // Given
        HttpMessage httpMessage = new HttpMessage();
        httpMessage.setResponseHeader("HTTP/1.1 200 OK");
        httpMessage.setResponseBody("123");
        // When
        boolean written = channel.writeOutbound(httpMessage);
        // Then
        assertThat(written, is(equalTo(true)));
        ByteBuf encoded = channel.readOutbound();
        assertNotNull(encoded);
        assertThat(
                encoded.toString(StandardCharsets.US_ASCII),
                is(equalTo("HTTP/1.1 200 OK\r\n\r\n123")));
        encoded.release();
        assertChannelStateEnd();
    }

    @Test
    void shouldEncodeResponseWithEmptyBodyInHttpMessage() throws Exception {
        // Given
        HttpMessage httpMessage = new HttpMessage();
        httpMessage.setResponseHeader("HTTP/1.1 200 OK");
        httpMessage.setResponseBody("");
        // When
        boolean written = channel.writeOutbound(httpMessage);
        // Then
        assertThat(written, is(equalTo(true)));
        ByteBuf encoded = channel.readOutbound();
        assertNotNull(encoded);
        assertThat(
                encoded.toString(StandardCharsets.US_ASCII),
                is(equalTo("HTTP/1.1 200 OK\r\n\r\n")));
        encoded.release();
        assertChannelStateEnd();
    }

    @Test
    void shouldNotEncodeDirectHttpResponseHeader() throws Exception {
        HttpResponseHeader header = new HttpResponseHeader("HTTP/1.1 200 OK");
        // When
        boolean written = channel.writeOutbound(header);
        // Then
        assertThat(written, is(equalTo(true)));
        assertSame(header, channel.readOutbound());
        assertChannelStateEnd();
    }

    @Test
    void shouldNotEncodeDirectHttpResponseBody() {
        HttpResponseBody body = new HttpResponseBody("123");
        // When
        boolean written = channel.writeOutbound(body);
        // Then
        assertThat(written, is(equalTo(true)));
        assertSame(body, channel.readOutbound());
        assertChannelStateEnd();
    }

    private void assertChannelStateEnd() {
        assertFalse(channel.finish());
        assertNull(channel.readInbound());
    }
}
