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
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.parosproxy.paros.network.HttpRequestHeader;

/** Unit test for {@link Alias}. */
class AliasUnitTest {

    @Test
    void shouldCreateWithGivenValues() {
        // Given
        String name = "example.org";
        boolean enabled = false;
        // When
        Alias alias = new Alias(name, enabled);
        // Then
        assertThat(alias.getName(), is(equalTo(name)));
        assertThat(alias.isEnabled(), is(equalTo(enabled)));
    }

    @Test
    void shouldThrowWhenCreatingWithNullName() {
        // Given
        String name = null;
        boolean enabled = false;
        // When / Then
        assertThrows(NullPointerException.class, () -> new Alias(name, enabled));
    }

    @Test
    void shouldCreateWithOtherInstance() {
        // Given
        String name = "example.org";
        boolean enabled = false;
        Alias other = new Alias(name, enabled);
        // When
        Alias alias = new Alias(other);
        // Then
        assertThat(alias.getName(), is(equalTo(name)));
        assertThat(alias.isEnabled(), is(equalTo(enabled)));
    }

    @Test
    void shouldThrowWhenCreatingWithNullOtherInstance() {
        // Given
        Alias other = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> new Alias(other));
    }

    @Test
    void shouldSetEnabledState() {
        // Given
        String name = "example.org";
        Alias alias = new Alias(name, true);
        boolean enabled = false;
        // When
        alias.setEnabled(enabled);
        // Then
        assertThat(alias.isEnabled(), is(equalTo(enabled)));
    }

    @Test
    void shouldSetName() {
        // Given
        Alias alias = new Alias("example.org", true);
        String name = "example.com";
        // When
        alias.setName(name);
        // Then
        assertThat(alias.getName(), is(equalTo(name)));
    }

    @Test
    void shouldThrowWhenSettingNullName() {
        // Given
        Alias alias = new Alias("example.org", true);
        String name = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> alias.setName(name));
    }

    @Test
    void shouldProduceConsistentHashCodes() {
        // Given
        Alias alias = new Alias("example.org", false);
        // When
        int hashCode = alias.hashCode();
        // Then
        assertThat(hashCode, is(equalTo(-1943962101)));
    }

    @Test
    void shouldBeEqualToItself() {
        // Given
        Alias alias = new Alias("example.org", false);
        // When
        boolean equals = alias.equals(alias);
        // Then
        assertThat(equals, is(equalTo(true)));
    }

    static Stream<Arguments> constructorArgsProvider() {
        return Stream.of(arguments("example.org", false), arguments("example.com", true));
    }

    @ParameterizedTest
    @MethodSource("constructorArgsProvider")
    void shouldBeEqualToDifferentAliasWithSameContents(String name, boolean enabled) {
        // Given
        Alias alias = new Alias(name, enabled);
        Alias otherEqualAlias = new Alias(name, enabled);
        // When
        boolean equals = alias.equals(otherEqualAlias);
        // Then
        assertThat(equals, is(equalTo(true)));
    }

    @Test
    void shouldNotBeEqualToNull() {
        // Given
        Alias alias = new Alias("example.org", false);
        // When
        boolean equals = alias.equals(null);
        // Then
        assertThat(equals, is(equalTo(false)));
    }

    static Stream<Arguments> differencesProvider() {
        String name = "example.org";
        String otherName = "example.com";
        return Stream.of(
                arguments(name, false, name, true),
                arguments(name, true, name, false),
                arguments(name, true, otherName, true),
                arguments(otherName, true, name, true));
    }

    @ParameterizedTest
    @MethodSource("differencesProvider")
    void shouldNotBeEqualToAliasWithDifferentValues(
            String name, boolean enabled, String otherName, boolean otherEnabled) {
        // Given
        Alias alias = new Alias(name, enabled);
        Alias otherAlias = new Alias(otherName, otherEnabled);
        // When
        boolean equals = alias.equals(otherAlias);
        // Then
        assertThat(equals, is(equalTo(false)));
    }

    @Test
    void shouldNotBeEqualToExtendedAlias() {
        // Given
        Alias alias = new Alias("example.org", false);
        Alias otherAlias = new Alias("example.org", false) {
                    // Anonymous Alias
                };
        // When
        boolean equals = alias.equals(otherAlias);
        // Then
        assertThat(equals, is(equalTo(false)));
    }

    @Test
    void shouldReturnTrueWhenTestingWithPresentName() {
        // Given
        String name = "example.org";
        Alias alias = new Alias(name, true);
        // When
        boolean result = alias.test(requestWithName(name));
        // Then
        assertThat(result, is(equalTo(true)));
    }

    @Test
    void shouldReturnFalseWhenTestingWithPresentNameButNotEnabled() {
        // Given
        boolean enabled = false;
        String name = "example.org";
        Alias alias = new Alias(name, enabled);
        // When
        boolean result = alias.test(requestWithName(name));
        // Then
        assertThat(result, is(equalTo(false)));
    }

    @Test
    void shouldReturnFalseWhenTestingWithNonPresentName() {
        // Given
        Alias alias = new Alias("example.org", true);
        // When
        boolean result = alias.test(requestWithName("example.com"));
        // Then
        assertThat(result, is(equalTo(false)));
    }

    private static HttpRequestHeader requestWithName(String name) {
        HttpRequestHeader requestHeader = mock(HttpRequestHeader.class);
        given(requestHeader.getHostName()).willReturn(name);
        return requestHeader;
    }
}
