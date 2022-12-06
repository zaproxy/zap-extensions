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
package org.zaproxy.addon.network.internal.client;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import java.net.Socket;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLEngine;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Unit test for {@link LaxTrustManager}. */
class LaxTrustManagerUnitTest {

    private LaxTrustManager laxTrustManager;

    @BeforeEach
    void setUp() {
        laxTrustManager = new LaxTrustManager();
    }

    @Test
    void shouldGetNullAcceptedIssuers() {
        // Given / When
        X509Certificate[] issuers = laxTrustManager.getAcceptedIssuers();
        // Then
        assertThat(issuers, is(nullValue()));
    }

    @Test
    void shouldTrustClient() {
        assertDoesNotThrow(() -> laxTrustManager.checkClientTrusted(null, null));
    }

    @Test
    void shouldTrustServer() {
        assertDoesNotThrow(() -> laxTrustManager.checkServerTrusted(null, null));
    }

    @Test
    void shouldTrustClientWithSocket() {
        assertDoesNotThrow(() -> laxTrustManager.checkClientTrusted(null, null, (Socket) null));
    }

    @Test
    void shouldTrustServerWithSocket() {
        assertDoesNotThrow(() -> laxTrustManager.checkServerTrusted(null, null, (Socket) null));
    }

    @Test
    void shouldTrustClientWithSslEngine() {
        assertDoesNotThrow(() -> laxTrustManager.checkClientTrusted(null, null, (SSLEngine) null));
    }

    @Test
    void shouldTrustServerWithSslEngine() {
        assertDoesNotThrow(() -> laxTrustManager.checkServerTrusted(null, null, (SSLEngine) null));
    }
}
