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
package org.zaproxy.addon.network.internal.client.apachev5;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.HttpEntity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Unit test for {@link OutgoingContentStrategy}. */
class OutgoingContentStrategyUnitTest {

    private OutgoingContentStrategy outgoingContentStrategy;

    @BeforeEach
    void setUp() {
        outgoingContentStrategy = new OutgoingContentStrategy();
    }

    @Test
    void shouldDetermineLengthFromEntity() throws Exception {
        // Given
        ClassicHttpRequest request = mock(ClassicHttpRequest.class);
        HttpEntity entity = mock(HttpEntity.class);
        long length = 1234L;
        given(entity.getContentLength()).willReturn(length);
        given(request.getEntity()).willReturn(entity);
        // When
        long determinedLength = outgoingContentStrategy.determineLength(request);
        // Then
        assertThat(determinedLength, is(equalTo(length)));
    }
}
