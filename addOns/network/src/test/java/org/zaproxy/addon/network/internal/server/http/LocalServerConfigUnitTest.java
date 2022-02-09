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
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.network.internal.TlsUtils;
import org.zaproxy.addon.network.internal.server.AliasChecker;
import org.zaproxy.addon.network.internal.server.http.LocalServerConfig.ServerMode;
import org.zaproxy.addon.network.server.Server;

/** Unit test for {@link LocalServerConfig}. */
class LocalServerConfigUnitTest {

    @Test
    void shouldCreateWithDefaultValues() {
        // Given / When
        LocalServerConfig server = new LocalServerConfig();
        // Then
        assertThat(server.getAddress(), is(equalTo("localhost")));
        assertThat(server.getPort(), is(equalTo(8080)));
        assertThat(server.getMode(), is(equalTo(LocalServerConfig.ServerMode.API_AND_PROXY)));
        assertThat(server.getTlsProtocols(), is(equalTo(TlsUtils.getSupportedProtocols())));
        assertThat(server.getTlsConfig(), is(notNullValue()));
        assertThat(server.isBehindNat(), is(equalTo(false)));
        assertThat(server.isRemoveAcceptEncoding(), is(equalTo(true)));
        assertThat(server.isDecodeResponse(), is(equalTo(true)));
        assertThat(server.isEnabled(), is(equalTo(true)));
    }

    static Stream<Arguments> serverData() {
        return Stream.of(
                arguments(
                        "127.0.0.1",
                        1001,
                        ServerMode.API_AND_PROXY,
                        true,
                        true,
                        true,
                        true,
                        true,
                        true),
                arguments("127.0.0.2", 1002, ServerMode.API, true, false, true, true, true, true),
                arguments("127.0.0.3", 1003, ServerMode.PROXY, false, true, true, true, true, true),
                arguments(
                        "127.0.0.4",
                        1004,
                        ServerMode.API_AND_PROXY,
                        true,
                        true,
                        false,
                        true,
                        true,
                        true),
                arguments(
                        "127.0.0.5",
                        1005,
                        ServerMode.API_AND_PROXY,
                        true,
                        true,
                        true,
                        false,
                        true,
                        true),
                arguments(
                        "127.0.0.6",
                        1006,
                        ServerMode.API_AND_PROXY,
                        true,
                        true,
                        true,
                        true,
                        false,
                        true),
                arguments(
                        "127.0.0.7",
                        1007,
                        ServerMode.API_AND_PROXY,
                        true,
                        true,
                        true,
                        true,
                        true,
                        false));
    }

    @ParameterizedTest
    @MethodSource("serverData")
    void shouldCreateFromInstance(
            String address,
            int port,
            ServerMode mode,
            boolean api,
            boolean proxy,
            boolean behindNat,
            boolean removeAcceptEncoding,
            boolean decodeResponse,
            boolean enabled) {
        // Given
        LocalServerConfig other = new LocalServerConfig();
        other.setAddress(address);
        other.setPort(port);
        other.setMode(mode);
        other.setBehindNat(behindNat);
        other.setRemoveAcceptEncoding(removeAcceptEncoding);
        other.setDecodeResponse(decodeResponse);
        other.setEnabled(enabled);
        // When
        LocalServerConfig server = new LocalServerConfig(other);
        // Then
        assertThat(server.getAddress(), is(equalTo(address)));
        assertThat(server.getPort(), is(equalTo(port)));
        assertThat(server.getMode(), is(equalTo(mode)));
        assertThat(server.getTlsProtocols(), is(notNullValue()));
        assertThat(server.getTlsConfig(), is(notNullValue()));
        assertThat(server.isBehindNat(), is(equalTo(behindNat)));
        assertThat(server.isRemoveAcceptEncoding(), is(equalTo(removeAcceptEncoding)));
        assertThat(server.isDecodeResponse(), is(equalTo(decodeResponse)));
        assertThat(server.isEnabled(), is(equalTo(enabled)));
    }

    @Test
    void shouldThrowWhenCreatingWithNullInstance() {
        // Given
        LocalServerConfig other = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> new LocalServerConfig(other));
    }

    @ParameterizedTest
    @MethodSource("serverData")
    void shouldUpdateFrom(
            String address,
            int port,
            ServerMode mode,
            boolean api,
            boolean proxy,
            boolean behindNat,
            boolean removeAcceptEncoding,
            boolean decodeResponse,
            boolean enabled) {
        // Given
        LocalServerConfig other = new LocalServerConfig();
        other.setAddress(address);
        other.setPort(port);
        other.setMode(mode);
        other.setBehindNat(behindNat);
        other.setRemoveAcceptEncoding(removeAcceptEncoding);
        other.setDecodeResponse(decodeResponse);
        other.setEnabled(enabled);
        LocalServerConfig server = new LocalServerConfig();
        // When
        boolean changed = server.updateFrom(other);
        // Then
        assertThat(changed, is(equalTo(true)));
        assertThat(server.getAddress(), is(equalTo(address)));
        assertThat(server.getPort(), is(equalTo(port)));
        assertThat(server.getMode(), is(equalTo(mode)));
        assertThat(server.getTlsProtocols(), is(notNullValue()));
        assertThat(server.getTlsConfig(), is(notNullValue()));
        assertThat(server.isBehindNat(), is(equalTo(behindNat)));
        assertThat(server.isRemoveAcceptEncoding(), is(equalTo(removeAcceptEncoding)));
        assertThat(server.isDecodeResponse(), is(equalTo(decodeResponse)));
        assertThat(server.isEnabled(), is(equalTo(enabled)));
    }

    @Test
    void shouldThrowWhenUpdatingWithNull() {
        // Given
        LocalServerConfig other = null;
        LocalServerConfig server = new LocalServerConfig();
        // When / Then
        assertThrows(NullPointerException.class, () -> server.updateFrom(other));
    }

    @ParameterizedTest
    @EnumSource(names = {"API_AND_PROXY", "API"})
    void shouldHaveApiEnabledIfModeAllows(ServerMode mode) {
        // Given
        LocalServerConfig server = new LocalServerConfig();
        // When
        server.setMode(mode);
        // Then
        assertThat(server.isApiEnabled(), is(equalTo(true)));
    }

    @Test
    void shouldNotHaveApiEnabledIfModeNotAllows() {
        // Given
        LocalServerConfig server = new LocalServerConfig();
        // When
        server.setMode(ServerMode.PROXY);
        // Then
        assertThat(server.isApiEnabled(), is(equalTo(false)));
    }

    @Test
    void shouldThrowWhenSettingNullMode() {
        // Given
        ServerMode mode = null;
        LocalServerConfig server = new LocalServerConfig();
        // When / Then
        assertThrows(NullPointerException.class, () -> server.setMode(mode));
    }

    @Test
    void shouldThrowWhenSettingNullAddress() {
        // Given
        String address = null;
        LocalServerConfig server = new LocalServerConfig();
        // When / Then
        assertThrows(NullPointerException.class, () -> server.setAddress(address));
    }

    @Test
    void shouldUseAnyAddressWhenEmpty() {
        // Given
        String address = "";
        LocalServerConfig server = new LocalServerConfig();
        // When
        server.setAddress(address);
        // Then
        assertThat(server.getAddress(), is(equalTo("0.0.0.0")));
        assertThat(server.isAnyLocalAddress(), is(equalTo(true)));
    }

    @Test
    void shouldHaveAnyAddress() {
        // Given
        String address = "0.0.0.0";
        LocalServerConfig server = new LocalServerConfig();
        // When
        server.setAddress(address);
        // Then
        assertThat(server.getAddress(), is(equalTo(address)));
        assertThat(server.isAnyLocalAddress(), is(equalTo(true)));
    }

    @Test
    void shouldNotHaveAnyAddressIfNotOne() {
        // Given
        String address = "127.0.0.1";
        LocalServerConfig server = new LocalServerConfig();
        // When
        server.setAddress(address);
        // Then
        assertThat(server.getAddress(), is(equalTo(address)));
        assertThat(server.isAnyLocalAddress(), is(equalTo(false)));
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, 0, Server.MAX_PORT + 1})
    void shouldThrowWhenSettingInvalidPort() {
        // Given
        String address = null;
        LocalServerConfig server = new LocalServerConfig();
        // When / Then
        assertThrows(NullPointerException.class, () -> server.setAddress(address));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldUseProvidedAliasChecker(boolean value) {
        // Given
        LocalServerConfig other = new LocalServerConfig();
        AliasChecker aliasChecker = mock(AliasChecker.class);
        given(aliasChecker.isAlias(any())).willReturn(value);
        LocalServerConfig server = new LocalServerConfig(other, aliasChecker);
        HttpRequestHeader requestHeader = mock(HttpRequestHeader.class);
        // When
        boolean alias = server.isAlias(requestHeader);
        // Then
        verify(aliasChecker).isAlias(requestHeader);
        assertThat(alias, is(equalTo(value)));
    }

    @Test
    void shouldNotBeAliasIfNoProvidedAliasChecker() {
        // Given
        LocalServerConfig other = new LocalServerConfig();
        AliasChecker aliasChecker = null;
        LocalServerConfig server = new LocalServerConfig(other, aliasChecker);
        HttpRequestHeader requestHeader = mock(HttpRequestHeader.class);
        // When
        boolean alias = server.isAlias(requestHeader);
        // Then
        assertThat(alias, is(equalTo(false)));
    }

    @Test
    void shouldProduceConsistentHashCode() {
        // Given
        LocalServerConfig server = new LocalServerConfig();
        LocalServerConfig other = new LocalServerConfig();
        // When
        int hashCode = server.hashCode();
        // Then
        assertThat(hashCode, is(equalTo(other.hashCode())));
    }

    @Test
    void shouldBeEqualToItself() {
        // Given
        LocalServerConfig server = new LocalServerConfig();
        // When
        boolean equals = server.equals(server);
        // Then
        assertThat(equals, is(equalTo(true)));
    }

    @Test
    void shouldNotBeEqualToNull() {
        // Given
        LocalServerConfig server = new LocalServerConfig();
        // When
        boolean equals = server.equals(null);
        // Then
        assertThat(equals, is(equalTo(false)));
    }

    @Test
    void shouldNotBeEqualToExtendedLocalServerConfig() {
        // Given
        LocalServerConfig server = new LocalServerConfig();
        LocalServerConfig otherLocalServerConfig = new LocalServerConfig() {
                    // Anonymous LocalServerConfig
                };
        // When
        boolean equals = server.equals(otherLocalServerConfig);
        // Then
        assertThat(equals, is(equalTo(false)));
    }
}
