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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.zaproxy.addon.network.internal.TlsUtils.TLS_V1_2;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.zaproxy.addon.network.internal.TlsUtils;

/** Unit test for {@link TlsConfig}. */
class TlsConfigUnitTest {

    @BeforeAll
    static void setup() {
        TlsUtils.getSupportedProtocols();
    }

    @Test
    void shouldCreateWithDefaults() {
        // Given / When
        TlsConfig tlsConfig = new TlsConfig();
        // Then
        assertThat(tlsConfig.getEnabledProtocols(), hasItem(TLS_V1_2));
    }

    @Test
    void shouldCreateWithProvidedProtocols() {
        // Given
        List<String> protocols = TlsUtils.getSupportedProtocols();
        // When
        TlsConfig tlsConfig = new TlsConfig(protocols);
        // Then
        assertThat(tlsConfig.getEnabledProtocols(), is(equalTo(protocols)));
    }

    @Test
    void shouldCreateWithProvidedProtocolsRemovingUnsupported() {
        // Given
        List<String> protocols = new ArrayList<>(TlsUtils.getSupportedProtocols());
        protocols.add("X");
        // When
        TlsConfig tlsConfig = new TlsConfig(protocols);
        // Then
        assertThat(tlsConfig.getEnabledProtocols(), is(equalTo(TlsUtils.getSupportedProtocols())));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"NotSupported", "SSLv2Hello"})
    void shouldThrowForUnsupportedProtocols(String protocols) {
        assertThrows(IllegalArgumentException.class, () -> new TlsConfig(Arrays.asList(protocols)));
    }

    @Test
    void shouldNotAllowToModifyReturnedProtocols() {
        // Given
        TlsConfig tlsConfig = new TlsConfig(TlsUtils.getSupportedProtocols());
        List<String> protocols = tlsConfig.getEnabledProtocols();
        // When / Then
        assertThrows(UnsupportedOperationException.class, () -> protocols.add("X"));
    }
}
