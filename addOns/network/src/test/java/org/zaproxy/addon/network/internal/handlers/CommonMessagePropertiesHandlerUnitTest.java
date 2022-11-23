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
package org.zaproxy.addon.network.internal.handlers;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;

import io.netty.channel.embedded.EmbeddedChannel;
import java.net.InetSocketAddress;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.network.internal.ChannelAttributes;

/** Unit test for {@link CommonMessagePropertiesHandler}. */
class CommonMessagePropertiesHandlerUnitTest {

    private static final InetSocketAddress SENDER_ADDRESS =
            new InetSocketAddress("127.0.0.1", 1234);

    protected EmbeddedChannel channel;

    @BeforeEach
    void setUp() {
        channel = new EmbeddedChannel(CommonMessagePropertiesHandler.getInstance());
        channel.attr(ChannelAttributes.REMOTE_ADDRESS).set(SENDER_ADDRESS);
    }

    @Test
    void shouldSetSenderAddress() {
        // Given
        InetSocketAddress senderAddress = new InetSocketAddress("127.0.0.3", 1234);
        channel.attr(ChannelAttributes.REMOTE_ADDRESS).set(senderAddress);
        HttpMessage msg = new HttpMessage();
        // When
        written(msg);
        // Then
        assertThat(
                msg.getRequestHeader().getSenderAddress(), is(equalTo(senderAddress.getAddress())));
        assertChannelState(msg);
    }

    @Test
    void shouldNotSetSenderAddressIfNotPresent() {
        // Given
        channel.attr(ChannelAttributes.REMOTE_ADDRESS).set(null);
        HttpMessage msg = new HttpMessage();
        // When
        written(msg);
        // Then
        assertThat(msg.getRequestHeader().getSenderAddress(), is(nullValue()));
        assertThat(msg.getUserObject(), is(nullValue()));
        assertChannelState(msg);
    }

    protected void written(HttpMessage message) {
        assertThat(channel.writeInbound(message), is(equalTo(true)));
    }

    protected void assertChannelState(HttpMessage msg) {
        assertThat(channel.finish(), is(equalTo(true)));
        assertThat(channel.readInbound(), is(equalTo(msg)));
    }
}
