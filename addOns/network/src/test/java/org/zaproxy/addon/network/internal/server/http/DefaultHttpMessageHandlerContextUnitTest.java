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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Unit test for {@link DefaultHttpMessageHandlerContext}. */
class DefaultHttpMessageHandlerContextUnitTest {

    private DefaultHttpMessageHandlerContext ctx;

    @BeforeEach
    void setUp() {
        ctx = new DefaultHttpMessageHandlerContext();
    }

    @Test
    void shouldHaveExceptedStatByDefault() {
        assertThat(ctx.isRecursive(), is(equalTo(false)));
        assertThat(ctx.isExcluded(), is(equalTo(false)));
        assertThat(ctx.isFromClient(), is(equalTo(true)));
        assertThat(ctx.isOverridden(), is(equalTo(false)));
        assertThat(ctx.isClose(), is(equalTo(false)));
    }

    @Test
    void shouldReset() {
        // Given
        ctx.setExcluded(true);
        ctx.setRecursive(true);
        ctx.handlingResponse();
        ctx.overridden();
        ctx.close();
        // When
        ctx.reset();
        // Then
        assertThat(ctx.isRecursive(), is(equalTo(false)));
        assertThat(ctx.isExcluded(), is(equalTo(false)));
        assertThat(ctx.isFromClient(), is(equalTo(true)));
        assertThat(ctx.isOverridden(), is(equalTo(false)));
        assertThat(ctx.isClose(), is(equalTo(false)));
    }

    @Test
    void shouldHandleResponse() {
        // Given
        ctx.overridden();
        ctx.close();
        // When
        ctx.handlingResponse();
        // Then
        assertThat(ctx.isRecursive(), is(equalTo(false)));
        assertThat(ctx.isExcluded(), is(equalTo(false)));
        assertThat(ctx.isFromClient(), is(equalTo(false)));
        assertThat(ctx.isOverridden(), is(equalTo(false)));
        assertThat(ctx.isClose(), is(equalTo(false)));
    }

    @Test
    void shouldPreserveRecursiveAndExcludedStateOnHandleResponse() {
        // Given
        ctx.setExcluded(true);
        ctx.setRecursive(true);
        // When
        ctx.handlingResponse();
        // Then
        assertThat(ctx.isRecursive(), is(equalTo(true)));
        assertThat(ctx.isExcluded(), is(equalTo(true)));
        assertThat(ctx.isFromClient(), is(equalTo(false)));
        assertThat(ctx.isOverridden(), is(equalTo(false)));
        assertThat(ctx.isClose(), is(equalTo(false)));
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
