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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import java.net.PasswordAuthentication;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.zaproxy.addon.network.internal.client.SocksProxy.Version;

/** Unit test for {@link SocksProxy}. */
class SocksProxyUnitTest {

    private static final String HOST = "localhost";
    private static final int PORT = 1080;
    private static final PasswordAuthentication EMPTY_CREDENTIALS =
            new PasswordAuthentication("", new char[] {});

    @Test
    void shouldNotCreateSocksProxyWithNullHost() {
        // Given
        String host = null;
        // When / Then
        assertThrows(
                NullPointerException.class,
                () -> new SocksProxy(host, PORT, Version.SOCKS5, true, EMPTY_CREDENTIALS));
    }

    @Test
    void shouldNotCreateSocksProxyWithEmptyHost() {
        // Given
        String host = "";
        // When / Then
        assertThrows(
                IllegalArgumentException.class,
                () -> new SocksProxy(host, PORT, Version.SOCKS5, true, EMPTY_CREDENTIALS));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, -1, 65546})
    void shouldNotCreateSocksProxyWithInvalidPort(int port) {
        assertThrows(
                IllegalArgumentException.class,
                () -> new SocksProxy(HOST, port, Version.SOCKS5, true, EMPTY_CREDENTIALS));
    }

    @Test
    void shouldNotCreateSocksProxyWithNullVersion() {
        // Given
        Version version = null;
        // When / Then
        assertThrows(
                NullPointerException.class,
                () -> new SocksProxy(HOST, PORT, version, true, EMPTY_CREDENTIALS));
    }

    @Test
    void shouldNotCreateSocksProxyWithNullCredentials() {
        // Given
        PasswordAuthentication credentials = null;
        // When / Then
        assertThrows(
                NullPointerException.class,
                () -> new SocksProxy(HOST, PORT, Version.SOCKS5, true, credentials));
    }

    @Test
    void shouldCreateSocksProxy() {
        // Given
        String host = "127.0.1.1";
        int port = 1234;
        Version version = Version.SOCKS5;
        boolean useDns = true;
        String username = "UserName";
        char[] password = {'1', '2', '3'};
        PasswordAuthentication credentials = new PasswordAuthentication(username, password);
        // When
        SocksProxy socksProxy = new SocksProxy(host, port, version, useDns, credentials);
        // Then
        assertThat(socksProxy.getHost(), is(equalTo(host)));
        assertThat(socksProxy.getPort(), is(equalTo(port)));
        assertThat(socksProxy.getVersion(), is(equalTo(version)));
        assertThat(socksProxy.isUseDns(), is(equalTo(useDns)));
        assertThat(socksProxy.getPasswordAuthentication().getUserName(), is(equalTo(username)));
        assertThat(socksProxy.getPasswordAuthentication().getPassword(), is(equalTo(password)));
    }

    @Test
    void shouldProduceConsistentHashCode() {
        // Given
        SocksProxy socksProxy =
                new SocksProxy(
                        "127.0.0.1",
                        9150,
                        Version.SOCKS5,
                        false,
                        new PasswordAuthentication("A", new char[] {'1'}));
        // When
        int hashCode = socksProxy.hashCode();
        // Then
        assertThat(hashCode, is(equalTo(693627553)));
    }

    @Test
    void shouldBeEqualToItself() {
        // Given
        SocksProxy socksProxy =
                new SocksProxy(HOST, PORT, Version.SOCKS4A, false, EMPTY_CREDENTIALS);
        // When
        boolean equals = socksProxy.equals(socksProxy);
        // Then
        assertThat(equals, is(equalTo(true)));
    }

    @Test
    void shouldBeEqualToDifferentSocksProxyWithSameContents() {
        // Given
        SocksProxy socksProxy =
                new SocksProxy(
                        HOST,
                        PORT,
                        Version.SOCKS4A,
                        false,
                        new PasswordAuthentication("A", new char[] {'1'}));
        SocksProxy otherEqualSocksProxy =
                new SocksProxy(
                        HOST,
                        PORT,
                        Version.SOCKS4A,
                        false,
                        new PasswordAuthentication("A", new char[] {'1'}));
        // When
        boolean equals = socksProxy.equals(otherEqualSocksProxy);
        // Then
        assertThat(equals, is(equalTo(true)));
    }

    @Test
    void shouldNotBeEqualToNull() {
        // Given
        SocksProxy socksProxy =
                new SocksProxy(HOST, PORT, Version.SOCKS4A, false, EMPTY_CREDENTIALS);
        // When
        boolean equals = socksProxy.equals(null);
        // Then
        assertThat(equals, is(equalTo(false)));
    }

    @Test
    void shouldNotBeEqualToSocksProxyWithJustDifferentHost() {
        // Given
        SocksProxy socksProxy =
                new SocksProxy(HOST, PORT, Version.SOCKS4A, false, EMPTY_CREDENTIALS);
        SocksProxy otherSocksProxy =
                new SocksProxy("example.com", PORT, Version.SOCKS4A, false, EMPTY_CREDENTIALS);
        // When
        boolean equals = socksProxy.equals(otherSocksProxy);
        // Then
        assertThat(equals, is(equalTo(false)));
    }

    @Test
    void shouldNotBeEqualToSocksProxyWithJustDifferentPort() {
        // Given
        SocksProxy socksProxy =
                new SocksProxy(HOST, PORT, Version.SOCKS4A, false, EMPTY_CREDENTIALS);
        SocksProxy otherSocksProxy =
                new SocksProxy(HOST, 1234, Version.SOCKS4A, false, EMPTY_CREDENTIALS);
        // When
        boolean equals = socksProxy.equals(otherSocksProxy);
        // Then
        assertThat(equals, is(equalTo(false)));
    }

    @Test
    void shouldNotBeEqualToSocksProxyWithJustDifferentVersion() {
        // Given
        SocksProxy socksProxy =
                new SocksProxy(HOST, PORT, Version.SOCKS4A, false, EMPTY_CREDENTIALS);
        SocksProxy otherSocksProxy =
                new SocksProxy(HOST, PORT, Version.SOCKS5, false, EMPTY_CREDENTIALS);
        // When
        boolean equals = socksProxy.equals(otherSocksProxy);
        // Then
        assertThat(equals, is(equalTo(false)));
    }

    @Test
    void shouldNotBeEqualToSocksProxyWithJustDifferentUseDns() {
        // Given
        SocksProxy socksProxy =
                new SocksProxy(HOST, PORT, Version.SOCKS4A, false, EMPTY_CREDENTIALS);
        SocksProxy otherSocksProxy =
                new SocksProxy(HOST, PORT, Version.SOCKS4A, true, EMPTY_CREDENTIALS);
        // When
        boolean equals = socksProxy.equals(otherSocksProxy);
        // Then
        assertThat(equals, is(equalTo(false)));
    }

    @Test
    void shouldNotBeEqualToSocksProxyWithJustDifferentUsername() {
        // Given
        SocksProxy socksProxy =
                new SocksProxy(
                        HOST,
                        PORT,
                        Version.SOCKS4A,
                        false,
                        new PasswordAuthentication("A", new char[] {'1'}));
        SocksProxy otherSocksProxy =
                new SocksProxy(
                        HOST,
                        PORT,
                        Version.SOCKS4A,
                        false,
                        new PasswordAuthentication("B", new char[] {'1'}));
        // When
        boolean equals = socksProxy.equals(otherSocksProxy);
        // Then
        assertThat(equals, is(equalTo(false)));
    }

    @Test
    void shouldNotBeEqualToSocksProxyWithJustDifferentPassword() {
        // Given
        SocksProxy socksProxy =
                new SocksProxy(
                        HOST,
                        PORT,
                        Version.SOCKS4A,
                        false,
                        new PasswordAuthentication("A", new char[] {'1'}));
        SocksProxy otherSocksProxy =
                new SocksProxy(
                        HOST,
                        PORT,
                        Version.SOCKS4A,
                        false,
                        new PasswordAuthentication("A", new char[] {'2'}));
        // When
        boolean equals = socksProxy.equals(otherSocksProxy);
        // Then
        assertThat(equals, is(equalTo(false)));
    }

    @Test
    void shouldBeEqualToExtendedSocksProxy() {
        // Given
        SocksProxy socksProxy =
                new SocksProxy(HOST, PORT, Version.SOCKS4A, false, EMPTY_CREDENTIALS);
        SocksProxy otherSocksProxy =
                new SocksProxy(HOST, PORT, Version.SOCKS4A, false, EMPTY_CREDENTIALS) {
                    // Anonymous SocksProxy
                };
        // When
        boolean equals = socksProxy.equals(otherSocksProxy);
        // Then
        assertThat(equals, is(equalTo(true)));
    }

    @Test
    void shouldNotBeEqualToDifferentType() {
        // Given
        SocksProxy socksProxy =
                new SocksProxy(HOST, PORT, Version.SOCKS4A, false, EMPTY_CREDENTIALS);
        String otherType = "";
        // When
        boolean equals = socksProxy.equals(otherType);
        // Then
        assertThat(equals, is(equalTo(false)));
    }

    @Test
    void shouldProduceConsistentStringRepresentation() {
        // Given
        SocksProxy socksProxy =
                new SocksProxy(
                        "localhost",
                        1080,
                        Version.SOCKS5,
                        true,
                        new PasswordAuthentication("A", new char[] {'1'}));
        // When
        String representation = socksProxy.toString();
        // Then
        assertThat(
                representation,
                is(
                        equalTo(
                                "[Host=localhost, Port=1080, Version=5, UseDns=true, UserName=A, Password=***]")));
    }

    @Test
    void shouldGetSocks4From4() {
        // Given
        String value = "4";
        // When
        Version version = Version.from(value);
        // Then
        assertThat(version, is(equalTo(Version.SOCKS4A)));
    }

    @Test
    void shouldGetSocks5From5() {
        // Given
        String value = "5";
        // When
        Version version = Version.from(value);
        // Then
        assertThat(version, is(equalTo(Version.SOCKS5)));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"3", "NotAVersion"})
    void shouldGetSocks5FromInvalidValues(String value) {
        // Given value
        // When
        Version version = Version.from(value);
        // Then
        assertThat(version, is(equalTo(Version.SOCKS5)));
    }

    @ParameterizedTest
    @MethodSource
    void shouldGetExpectedVersionNumberFromVersion(Version version, int number) {
        // Given version, number
        // When / Then
        assertThat(version.number(), is(equalTo(number)));
    }

    static Stream<Arguments> shouldGetExpectedVersionNumberFromVersion() {
        return Stream.of(arguments(Version.SOCKS4A, 4), arguments(Version.SOCKS5, 5));
    }
}
