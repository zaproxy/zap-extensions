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

import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.HttpRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.zaproxy.addon.network.ConnectionOptions;

/** Unit test of {@link ConnectRequestInterceptor}. */
class ConnectRequestInterceptorUnitTest {

    private ConnectionOptions connectionOptions;
    private ConnectRequestInterceptor connectRequestInterceptor;

    @BeforeEach
    void setUp() {
        connectionOptions = mock(ConnectionOptions.class);
        connectRequestInterceptor = new ConnectRequestInterceptor(connectionOptions);
    }

    @Test
    void shouldAddUserAgentIfDefined() {
        // Given
        String userAgent = "Custom User-Agent";
        given(connectionOptions.getDefaultUserAgent()).willReturn(userAgent);
        HttpRequest request = mock(HttpRequest.class);
        // When
        connectRequestInterceptor.process(request, null, null);
        // Then
        verify(request).addHeader(HttpHeaders.USER_AGENT, userAgent);
    }

    @ParameterizedTest
    @NullAndEmptySource
    void shouldNotAddUserAgentIfNullOrEmpty(String userAgent) {
        // Given
        given(connectionOptions.getDefaultUserAgent()).willReturn(userAgent);
        HttpRequest request = mock(HttpRequest.class);
        // When
        connectRequestInterceptor.process(request, null, null);
        // Then
        verifyNoInteractions(request);
    }
}
