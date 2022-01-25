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

import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import io.netty.channel.ChannelInboundHandler;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.channel.group.ChannelGroup;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Unit test for {@link ChannelGroupHandler}. */
class ChannelGroupHandlerUnitTest {

    private ChannelGroup channelGroup;

    @BeforeEach
    void setUp() {
        channelGroup = mock(ChannelGroup.class);
    }

    @Test
    void shouldThrowIfChannelGroupIsNull() throws Exception {
        // Given
        ChannelGroup channelGroup = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> new ChannelGroupHandler(channelGroup));
    }

    @Test
    void shouldAddActivatedChannelToGroup() throws Exception {
        // Given
        ChannelGroupHandler channelGroupHandler = new ChannelGroupHandler(channelGroup);
        // When
        EmbeddedChannel channel = new EmbeddedChannel(channelGroupHandler);
        // Then
        verify(channelGroup).add(channel);
    }

    @Test
    void shouldRemoveItselfFromPipeline() throws Exception {
        // Given
        ChannelGroupHandler channelGroupHandler = new ChannelGroupHandler(channelGroup);
        // When
        EmbeddedChannel channel = new EmbeddedChannel(channelGroupHandler);
        // Then
        assertThat(channel.pipeline().get(ChannelGroupHandler.class), is(nullValue()));
    }

    @Test
    void shouldNotifyNextHandlerChannelActivated() throws Exception {
        // Given
        ChannelGroupHandler channelGroupHandler = new ChannelGroupHandler(channelGroup);
        ChannelInboundHandler nextHandler = mock(ChannelInboundHandler.class);
        // When
        new EmbeddedChannel(channelGroupHandler, nextHandler);
        // Then
        verify(nextHandler).channelActive(any());
    }
}
