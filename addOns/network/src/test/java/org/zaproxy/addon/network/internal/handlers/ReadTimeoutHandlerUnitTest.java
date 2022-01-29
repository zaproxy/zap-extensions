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

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import io.netty.channel.ChannelInboundHandler;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.timeout.ReadTimeoutException;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.zaproxy.addon.network.internal.ChannelAttributes;

/** Unit test for {@link ReadTimeoutHandler}. */
class ReadTimeoutHandlerUnitTest {

    @ParameterizedTest
    @ValueSource(ints = {-1, 0})
    void shouldThrowIfInvalidTimeout(int timeout) throws Exception {
        assertThrows(
                IllegalArgumentException.class,
                () -> new ReadTimeoutHandler(timeout, TimeUnit.SECONDS));
    }

    @Test
    void shouldThrowIfUnitIsNull() throws Exception {
        // Given
        TimeUnit unit = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> new ReadTimeoutHandler(1, unit));
    }

    @Test
    void shouldTimeoutAfterSpecifiedValue() throws Exception {
        // Given
        int millis = 250;
        ReadTimeoutHandler readTimeoutHandler =
                new ReadTimeoutHandler(millis, TimeUnit.MILLISECONDS);
        ChannelInboundHandler nextHandler = mock(ChannelInboundHandler.class);
        // When
        EmbeddedChannel channel = new EmbeddedChannel(readTimeoutHandler, nextHandler);
        channel.attr(ChannelAttributes.PROCESSING_MESSAGE).set(Boolean.FALSE);
        Thread.sleep(millis * 2);
        channel.runPendingTasks();
        // Then
        verify(nextHandler).exceptionCaught(any(), eq(ReadTimeoutException.INSTANCE));
    }

    @Test
    void shouldNotTimeoutIfProcessingMessage() throws Exception {
        // Given
        int millis = 250;
        ReadTimeoutHandler readTimeoutHandler =
                new ReadTimeoutHandler(millis, TimeUnit.MILLISECONDS);
        ChannelInboundHandler nextHandler = mock(ChannelInboundHandler.class);
        // When
        EmbeddedChannel channel = new EmbeddedChannel(readTimeoutHandler, nextHandler);
        channel.attr(ChannelAttributes.PROCESSING_MESSAGE).set(Boolean.TRUE);
        Thread.sleep(millis * 2);
        channel.runPendingTasks();
        // Then
        verify(nextHandler, times(0)).exceptionCaught(any(), eq(ReadTimeoutException.INSTANCE));
    }

    @Test
    void shouldKeepInPipelineAfterTimeout() throws Exception {
        // Given
        int millis = 250;
        ReadTimeoutHandler readTimeoutHandler =
                new ReadTimeoutHandler(millis, TimeUnit.MILLISECONDS);
        ChannelInboundHandler nextHandler = mock(ChannelInboundHandler.class);
        // When
        EmbeddedChannel channel = new EmbeddedChannel(readTimeoutHandler, nextHandler);
        Thread.sleep(millis * 2);
        channel.runPendingTasks();
        // Then
        assertThat(channel.pipeline().get(ReadTimeoutHandler.class), is(notNullValue()));
    }
}
