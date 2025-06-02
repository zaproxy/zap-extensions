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
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.zaproxy.addon.network.internal.TlsUtils.APPLICATION_PROTOCOL_HTTP_1_1;
import static org.zaproxy.addon.network.internal.TlsUtils.APPLICATION_PROTOCOL_HTTP_2;
import static org.zaproxy.addon.network.internal.TlsUtils.TLS_V1_2;
import static org.zaproxy.addon.network.internal.TlsUtils.getSupportedApplicationProtocols;
import static org.zaproxy.addon.network.internal.TlsUtils.getSupportedTlsProtocols;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

/** Unit test for {@link TlsConfig}. */
class TlsConfigUnitTest {

    private static final List<String> TLS_PROTOCOLS = List.of(TLS_V1_2);
    private static final List<String> APPLICATION_PROTOCOLS =
            List.of(APPLICATION_PROTOCOL_HTTP_1_1, APPLICATION_PROTOCOL_HTTP_2);

    @BeforeAll
    static void setup() {
        getSupportedTlsProtocols();
    }

    @Test
    void shouldCreateWithDefaults() {
        // Given / When
        TlsConfig tlsConfig = new TlsConfig();
        // Then
        assertThat(tlsConfig.getTlsProtocols(), hasItem(TLS_V1_2));
        assertThat(tlsConfig.isAlpnEnabled(), is(equalTo(true)));
        assertThat(
                tlsConfig.getApplicationProtocols(),
                is(equalTo(getSupportedApplicationProtocols())));
    }

    @Test
    void shouldCreateWithProvidedTlsProtocols() {
        // Given
        List<String> protocols = getSupportedTlsProtocols();
        // When
        TlsConfig tlsConfig = new TlsConfig(protocols, false, getSupportedApplicationProtocols());
        // Then
        assertThat(tlsConfig.getTlsProtocols(), is(equalTo(protocols)));
    }

    @Test
    void shouldCreateWithProvidedTlsProtocolsRemovingUnsupported() {
        // Given
        List<String> protocols = new ArrayList<>(getSupportedTlsProtocols());
        protocols.add("X");
        // When
        TlsConfig tlsConfig = new TlsConfig(protocols, false, getSupportedApplicationProtocols());
        // Then
        assertThat(tlsConfig.getTlsProtocols(), is(equalTo(getSupportedTlsProtocols())));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"NotSupported", "SSLv2Hello"})
    void shouldThrowForUnsupportedTlsProtocols(String protocols) {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new TlsConfig(
                                Arrays.asList(protocols),
                                false,
                                getSupportedApplicationProtocols()));
    }

    @Test
    void shouldNotAllowToModifyReturnedTlsProtocols() {
        // Given
        TlsConfig tlsConfig =
                new TlsConfig(getSupportedTlsProtocols(), false, APPLICATION_PROTOCOLS);
        List<String> protocols = tlsConfig.getTlsProtocols();
        // When / Then
        assertThrows(UnsupportedOperationException.class, () -> protocols.add("X"));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldCreateWithProvidedAlpnEnabled(boolean alpnEnabled) {
        // Given / When
        TlsConfig tlsConfig =
                new TlsConfig(
                        getSupportedTlsProtocols(),
                        alpnEnabled,
                        getSupportedApplicationProtocols());
        // Then
        assertThat(tlsConfig.isAlpnEnabled(), is(equalTo(alpnEnabled)));
    }

    @Test
    void shouldCreateWithProvidedApplicationProtocols() {
        // Given
        List<String> protocols = APPLICATION_PROTOCOLS;
        // When
        TlsConfig tlsConfig = new TlsConfig(getSupportedTlsProtocols(), false, protocols);
        // Then
        assertThat(tlsConfig.getApplicationProtocols(), is(equalTo(protocols)));
    }

    @Test
    void shouldCreateWithProvidedApplicationProtocolsRemovingUnsupported() {
        // Given
        List<String> protocols = new ArrayList<>(getSupportedApplicationProtocols());
        protocols.add("X");
        // When
        TlsConfig tlsConfig = new TlsConfig(getSupportedTlsProtocols(), false, protocols);
        // Then
        assertThat(tlsConfig.getApplicationProtocols(), is(equalTo(APPLICATION_PROTOCOLS)));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"h1"})
    void shouldThrowForUnsupportedApplicationProtocols(String protocols) {
        assertThrows(
                IllegalArgumentException.class,
                () -> new TlsConfig(getSupportedTlsProtocols(), false, Arrays.asList(protocols)));
    }

    @Test
    void shouldNotAllowToModifyReturnedApplicationProtocols() {
        // Given
        TlsConfig tlsConfig =
                new TlsConfig(getSupportedTlsProtocols(), false, APPLICATION_PROTOCOLS);
        List<String> protocols = tlsConfig.getApplicationProtocols();
        // When / Then
        assertThrows(UnsupportedOperationException.class, () -> protocols.add("X"));
    }

    @Test
    void shouldProduceConsistentHashCodes() {
        // Given
        TlsConfig tlsConfig = new TlsConfig(TLS_PROTOCOLS, true, APPLICATION_PROTOCOLS);
        // When
        int hashCode = tlsConfig.hashCode();
        // Then
        assertThat(hashCode, is(equalTo(2014107303)));
    }

    @Test
    void shouldBeEqualToItself() {
        // Given
        TlsConfig tlsConfig = new TlsConfig();
        // When
        boolean equals = tlsConfig.equals(tlsConfig);
        // Then
        assertThat(equals, is(equalTo(true)));
    }

    static Stream<Arguments> constructorArgsProvider() {
        return Stream.of(
                arguments(getSupportedTlsProtocols(), false, APPLICATION_PROTOCOLS),
                arguments(TLS_PROTOCOLS, true, APPLICATION_PROTOCOLS));
    }

    @ParameterizedTest
    @MethodSource("constructorArgsProvider")
    void shouldBeEqualToDifferentTlsConfigWithSameContents(
            List<String> protocols, boolean alpnEnabled, List<String> applicationProtocols) {
        // Given
        TlsConfig tlsConfig = new TlsConfig(protocols, alpnEnabled, applicationProtocols);
        TlsConfig otherEqualTlsConfig = new TlsConfig(protocols, alpnEnabled, applicationProtocols);
        // When
        boolean equals = tlsConfig.equals(otherEqualTlsConfig);
        // Then
        assertThat(equals, is(equalTo(true)));
    }

    @Test
    void shouldNotBeEqualToNull() {
        // Given
        TlsConfig tlsConfig = new TlsConfig();
        // When
        boolean equals = tlsConfig.equals(null);
        // Then
        assertThat(equals, is(equalTo(false)));
    }

    static Stream<Arguments> differencesProvider() {
        return Stream.of(
                arguments(
                        getSupportedTlsProtocols(),
                        true,
                        getSupportedApplicationProtocols(),
                        TLS_PROTOCOLS,
                        true,
                        getSupportedApplicationProtocols()),
                arguments(
                        TLS_PROTOCOLS,
                        true,
                        getSupportedApplicationProtocols(),
                        getSupportedTlsProtocols(),
                        true,
                        getSupportedApplicationProtocols()),
                arguments(
                        getSupportedTlsProtocols(),
                        true,
                        getSupportedApplicationProtocols(),
                        getSupportedTlsProtocols(),
                        false,
                        getSupportedApplicationProtocols()),
                arguments(
                        getSupportedTlsProtocols(),
                        false,
                        getSupportedApplicationProtocols(),
                        getSupportedTlsProtocols(),
                        true,
                        getSupportedApplicationProtocols()));
    }

    @ParameterizedTest
    @MethodSource("differencesProvider")
    void shouldNotBeEqualToTlsConfigWithDifferentTlsProtocols(
            List<String> protocols,
            boolean alpnEnabled,
            List<String> applicationProcotols,
            List<String> otherProtocols,
            boolean otherAlpnEnabled,
            List<String> otherApplicationProcotols) {
        assumeTrue(!protocols.equals(otherProtocols), "Requires different protocols.");
        // Given
        TlsConfig tlsConfig = new TlsConfig(protocols, alpnEnabled, applicationProcotols);
        TlsConfig otherTlsConfig =
                new TlsConfig(otherProtocols, otherAlpnEnabled, otherApplicationProcotols);
        // When
        boolean equals = tlsConfig.equals(otherTlsConfig);
        // Then
        assertThat(equals, is(equalTo(false)));
    }

    @Test
    void shouldBeEqualToExtendedTlsConfig() {
        // Given
        TlsConfig tlsConfig = new TlsConfig();
        TlsConfig otherTlsConfig = new TlsConfig() {
                    // Anonymous TlsConfig
                };
        // When
        boolean equals = tlsConfig.equals(otherTlsConfig);
        // Then
        assertThat(equals, is(equalTo(true)));
    }
}
