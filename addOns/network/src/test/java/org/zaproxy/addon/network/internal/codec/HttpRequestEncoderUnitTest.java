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
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.network.HttpRequestBody;

/** Unit test for {@link HttpRequestEncoder}. */
class HttpRequestEncoderUnitTest {

    private EmbeddedChannel channel;

    @BeforeEach
    void setUp() {
        channel = new EmbeddedChannel(HttpRequestEncoder.getInstance());
    }

    @Test
    void shouldBeSharable() {
        assertThat(HttpRequestEncoder.getInstance().isSharable(), is(equalTo(true)));
    }

    @Test
    void shouldEncodeRequestInHttpMessage() throws Exception {
        // Given
        HttpMessage httpMessage = new HttpMessage();
        httpMessage.setRequestHeader("POST http://127.0.0.1/ HTTP/1.1\r\nHost: 127.0.0.1");
        httpMessage.setRequestBody("123");
        // When
        boolean written = channel.writeOutbound(httpMessage);
        // Then
        assertThat(written, is(equalTo(true)));
        ByteBuf encoded = channel.readOutbound();
        assertNotNull(encoded);
        assertThat(
                encoded.toString(StandardCharsets.US_ASCII),
                is(equalTo("POST http://127.0.0.1/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n123")));
        encoded.release();
        assertChannelStateEnd();
    }

    @Test
    void shouldEncodeRequestWithEmptyBodyInHttpMessage() throws Exception {
        // Given
        HttpMessage httpMessage = new HttpMessage();
        httpMessage.setRequestHeader("POST http://127.0.0.1/ HTTP/1.1\r\nHost: 127.0.0.1");
        httpMessage.setRequestBody("");
        // When
        boolean written = channel.writeOutbound(httpMessage);
        // Then
        assertThat(written, is(equalTo(true)));
        ByteBuf encoded = channel.readOutbound();
        assertNotNull(encoded);
        assertThat(
                encoded.toString(StandardCharsets.US_ASCII),
                is(equalTo("POST http://127.0.0.1/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")));
        encoded.release();
        assertChannelStateEnd();
    }

    @Test
    void shouldNotEncodeDirectHttpRequestHeader() throws Exception {
        HttpRequestHeader header = new HttpRequestHeader("GET / HTTP/1.1\r\nHost: 127.0.0.1");
        // When
        boolean written = channel.writeOutbound(header);
        // Then
        assertThat(written, is(equalTo(true)));
        assertSame(header, channel.readOutbound());
        assertChannelStateEnd();
    }

    @Test
    void shouldNotEncodeDirectHttpRequestBody() {
        HttpRequestBody body = new HttpRequestBody("123");
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
