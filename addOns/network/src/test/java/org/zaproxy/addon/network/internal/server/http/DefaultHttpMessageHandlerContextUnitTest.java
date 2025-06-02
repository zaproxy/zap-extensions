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
package org.zaproxy.addon.network.internal.server.http;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import io.netty.channel.Channel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.network.HttpMessage;

/** Unit test for {@link DefaultHttpMessageHandlerContext}. */
class DefaultHttpMessageHandlerContextUnitTest {

    private DefaultHttpMessageHandlerContext ctx;

    private Channel channel;
    private RecursiveRequestChecker recursiveRequestChecker;

    @BeforeEach
    void setUp() {
        channel = mock(Channel.class);
        recursiveRequestChecker = mock(RecursiveRequestChecker.class);

        ctx = new DefaultHttpMessageHandlerContext(channel, recursiveRequestChecker);
    }

    @Test
    void shouldThrowOnNullChannel() {
        // Given
        channel = null;
        // When / Then
        assertThrows(
                NullPointerException.class,
                () -> new DefaultHttpMessageHandlerContext(channel, recursiveRequestChecker));
    }

    @Test
    void shouldThrowOnNullRecursiveRequestChecker() {
        // Given
        recursiveRequestChecker = null;
        // When / Then
        assertThrows(
                NullPointerException.class,
                () -> new DefaultHttpMessageHandlerContext(channel, recursiveRequestChecker));
    }

    @Test
    void shouldHaveExceptedStateByDefault() {
        assertThat(ctx.isRecursive(), is(equalTo(false)));
        assertThat(ctx.isExcluded(), is(equalTo(false)));
        assertThat(ctx.isFromClient(), is(equalTo(true)));
        assertThat(ctx.isOverridden(), is(equalTo(false)));
        assertThat(ctx.isClose(), is(equalTo(false)));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldUpdateRecursiveStateUsingProvidedData(boolean recursive) {
        // Given
        HttpMessage msg = mock(HttpMessage.class);
        given(recursiveRequestChecker.isRecursive(channel, msg)).willReturn(recursive);
        // When
        ctx.updateRecursiveState(msg);
        // Then
        verify(recursiveRequestChecker).isRecursive(channel, msg);
        assertThat(ctx.isRecursive(), is(equalTo(recursive)));
    }

    @Test
    void shouldHandleResponse() {
        // Given
        HttpMessage msg = mock(HttpMessage.class);
        ctx.overridden();
        ctx.close();
        // When
        ctx.handlingResponse(msg);
        // Then
        assertThat(ctx.isRecursive(), is(equalTo(false)));
        assertThat(ctx.isExcluded(), is(equalTo(false)));
        assertThat(ctx.isFromClient(), is(equalTo(false)));
        assertThat(ctx.isOverridden(), is(equalTo(false)));
        assertThat(ctx.isClose(), is(equalTo(false)));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldPreserveRecursiveAndExcludedStateOnHandleResponse(boolean recursive) {
        // Given
        HttpMessage msg = mock(HttpMessage.class);
        ctx.setExcluded(true);
        given(recursiveRequestChecker.isRecursive(channel, msg)).willReturn(recursive);
        // When
        ctx.handlingResponse(msg);
        // Then
        assertThat(ctx.isRecursive(), is(equalTo(recursive)));
        assertThat(ctx.isExcluded(), is(equalTo(true)));
        assertThat(ctx.isFromClient(), is(equalTo(false)));
        assertThat(ctx.isOverridden(), is(equalTo(false)));
        assertThat(ctx.isClose(), is(equalTo(false)));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldIgnoreRecursiveStateUpdateAfterHandlingResponse(boolean recursive) {
        // Given
        HttpMessage msg = mock(HttpMessage.class);
        ctx.setExcluded(true);
        given(recursiveRequestChecker.isRecursive(channel, msg)).willReturn(recursive, !recursive);
        ctx.handlingResponse(msg);
        // When
        ctx.updateRecursiveState(msg);
        // Then
        assertThat(ctx.isRecursive(), is(equalTo(recursive)));
    }

    @Test
    void shouldOverride() {
        // Given / When
        ctx.overridden();
        // Then
        assertThat(ctx.isOverridden(), is(equalTo(true)));
    }

    @Test
    void shouldClose() {
        // Given / When
        ctx.close();
        // Then
        assertThat(ctx.isClose(), is(equalTo(true)));
    }
}
