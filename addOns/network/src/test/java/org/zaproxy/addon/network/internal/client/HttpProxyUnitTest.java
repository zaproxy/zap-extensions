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

import java.net.PasswordAuthentication;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Unit test for {@link HttpProxy}. */
class HttpProxyUnitTest {

    private static final String HOST = "localhost";
    private static final int PORT = 8090;
    private static final String REALM = "realm";
    private static final PasswordAuthentication EMPTY_CREDENTIALS =
            new PasswordAuthentication("", new char[] {});

    @Test
    void shouldNotCreateHttpProxyWithNullHost() {
        // Given
        String host = null;
        // When / Then
        assertThrows(
                NullPointerException.class,
                () -> new HttpProxy(host, PORT, REALM, EMPTY_CREDENTIALS));
    }

    @Test
    void shouldNotCreateHttpProxyWithEmptyHost() {
        // Given
        String host = "";
        // When / Then
        assertThrows(
                IllegalArgumentException.class,
                () -> new HttpProxy(host, PORT, REALM, EMPTY_CREDENTIALS));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, -1, 65546})
    void shouldNotCreateHttpProxyWithInvalidPort(int port) {
        assertThrows(
                IllegalArgumentException.class,
                () -> new HttpProxy(HOST, port, REALM, EMPTY_CREDENTIALS));
    }

    @Test
    void shouldNotCreateHttpProxyWithNullRealm() {
        // Given
        String realm = null;
        // When / Then
        assertThrows(
                NullPointerException.class,
                () -> new HttpProxy(HOST, PORT, realm, EMPTY_CREDENTIALS));
    }

    @Test
    void shouldNotCreateHttpProxyWithNullCredentials() {
        // Given
        PasswordAuthentication credentials = null;
        // When / Then
        assertThrows(
                NullPointerException.class, () -> new HttpProxy(HOST, PORT, REALM, credentials));
    }

    @Test
    void shouldCreateHttpProxy() {
        // Given
        String host = "127.0.1.1";
        int port = 1234;
        String realm = "Realm";
        String username = "UserName";
        char[] password = {'1', '2', '3'};
        PasswordAuthentication credentials = new PasswordAuthentication(username, password);
        // When
        HttpProxy httpProxy = new HttpProxy(host, port, realm, credentials);
        // Then
        assertThat(httpProxy.getHost(), is(equalTo(host)));
        assertThat(httpProxy.getPort(), is(equalTo(port)));
        assertThat(httpProxy.getRealm(), is(equalTo(realm)));
        assertThat(httpProxy.getPasswordAuthentication().getUserName(), is(equalTo(username)));
        assertThat(httpProxy.getPasswordAuthentication().getPassword(), is(equalTo(password)));
    }

    @Test
    void shouldProduceConsistentHashCode() {
        // Given
        HttpProxy httpProxy =
                new HttpProxy(
                        "127.0.0.1",
                        8190,
                        "realm A",
                        new PasswordAuthentication("A", new char[] {'1'}));
        // When
        int hashCode = httpProxy.hashCode();
        // Then
        assertThat(hashCode, is(equalTo(-27052655)));
    }

    @Test
    void shouldBeEqualToItself() {
        // Given
        HttpProxy httpProxy = new HttpProxy(HOST, PORT, REALM, EMPTY_CREDENTIALS);
        // When
        boolean equals = httpProxy.equals(httpProxy);
        // Then
        assertThat(equals, is(equalTo(true)));
    }

    @Test
    void shouldBeEqualToDifferentHttpProxyWithSameContents() {
        // Given
        HttpProxy httpProxy =
                new HttpProxy(HOST, PORT, REALM, new PasswordAuthentication("A", new char[] {'1'}));
        HttpProxy otherEqualHttpProxy =
                new HttpProxy(HOST, PORT, REALM, new PasswordAuthentication("A", new char[] {'1'}));
        // When
        boolean equals = httpProxy.equals(otherEqualHttpProxy);
        // Then
        assertThat(equals, is(equalTo(true)));
    }

    @Test
    void shouldNotBeEqualToNull() {
        // Given
        HttpProxy httpProxy = new HttpProxy(HOST, PORT, REALM, EMPTY_CREDENTIALS);
        // When
        boolean equals = httpProxy.equals(null);
        // Then
        assertThat(equals, is(equalTo(false)));
    }

    @Test
    void shouldNotBeEqualToHttpProxyWithJustDifferentHost() {
        // Given
        HttpProxy httpProxy = new HttpProxy(HOST, PORT, REALM, EMPTY_CREDENTIALS);
        HttpProxy otherHttpProxy = new HttpProxy("example.com", PORT, REALM, EMPTY_CREDENTIALS);
        // When
        boolean equals = httpProxy.equals(otherHttpProxy);
        // Then
        assertThat(equals, is(equalTo(false)));
    }

    @Test
    void shouldNotBeEqualToHttpProxyWithJustDifferentPort() {
        // Given
        HttpProxy httpProxy = new HttpProxy(HOST, PORT, REALM, EMPTY_CREDENTIALS);
        HttpProxy otherHttpProxy = new HttpProxy(HOST, 1234, REALM, EMPTY_CREDENTIALS);
        // When
        boolean equals = httpProxy.equals(otherHttpProxy);
        // Then
        assertThat(equals, is(equalTo(false)));
    }

    @Test
    void shouldNotBeEqualToHttpProxyWithJustDifferentRealm() {
        // Given
        HttpProxy httpProxy = new HttpProxy(HOST, PORT, REALM, EMPTY_CREDENTIALS);
        HttpProxy otherHttpProxy = new HttpProxy(HOST, PORT, "Other Realm", EMPTY_CREDENTIALS);
        // When
        boolean equals = httpProxy.equals(otherHttpProxy);
        // Then
        assertThat(equals, is(equalTo(false)));
    }

    @Test
    void shouldNotBeEqualToHttpProxyWithJustDifferentUsername() {
        // Given
        HttpProxy httpProxy =
                new HttpProxy(HOST, PORT, REALM, new PasswordAuthentication("A", new char[] {'1'}));
        HttpProxy otherHttpProxy =
                new HttpProxy(HOST, PORT, REALM, new PasswordAuthentication("B", new char[] {'1'}));
        // When
        boolean equals = httpProxy.equals(otherHttpProxy);
        // Then
        assertThat(equals, is(equalTo(false)));
    }

    @Test
    void shouldNotBeEqualToHttpProxyWithJustDifferentPassword() {
        // Given
        HttpProxy httpProxy =
                new HttpProxy(HOST, PORT, REALM, new PasswordAuthentication("A", new char[] {'1'}));
        HttpProxy otherHttpProxy =
                new HttpProxy(HOST, PORT, REALM, new PasswordAuthentication("A", new char[] {'2'}));
        // When
        boolean equals = httpProxy.equals(otherHttpProxy);
        // Then
        assertThat(equals, is(equalTo(false)));
    }

    @Test
    void shouldBeEqualToExtendedHttpProxy() {
        // Given
        HttpProxy httpProxy = new HttpProxy(HOST, PORT, REALM, EMPTY_CREDENTIALS);
        HttpProxy otherHttpProxy = new HttpProxy(HOST, PORT, REALM, EMPTY_CREDENTIALS) {
                    // Anonymous HttpProxy
                };
        // When
        boolean equals = httpProxy.equals(otherHttpProxy);
        // Then
        assertThat(equals, is(equalTo(true)));
    }

    @Test
    void shouldNotBeEqualToDifferentType() {
        // Given
        HttpProxy httpProxy = new HttpProxy(HOST, PORT, REALM, EMPTY_CREDENTIALS);
        String otherType = "";
        // When
        boolean equals = httpProxy.equals(otherType);
        // Then
        assertThat(equals, is(equalTo(false)));
    }

    @Test
    void shouldProduceConsistentStringRepresentation() {
        // Given
        HttpProxy httpProxy =
                new HttpProxy(
                        "localhost",
                        8090,
                        "realm",
                        new PasswordAuthentication("A", new char[] {'1'}));
        // When
        String representation = httpProxy.toString();
        // Then
        assertThat(
                representation,
                is(equalTo("[Host=localhost, Port=8090, Realm=realm, UserName=A, Password=***]")));
    }
}
