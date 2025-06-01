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
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

/** Unit test for {@link HttpProxyExclusion}. */
class HttpProxyExclusionUnitTest {

    @Test
    void shouldCreateWithGivenValues() {
        // Given
        Pattern host = Pattern.compile("example.org");
        boolean enabled = false;
        // When
        HttpProxyExclusion exclusion = new HttpProxyExclusion(host, enabled);
        // Then
        assertThat(exclusion.getHost(), is(equalTo(host)));
        assertThat(exclusion.isEnabled(), is(equalTo(enabled)));
    }

    @Test
    void shouldThrowWhenCreatingWithNullHost() {
        // Given
        Pattern host = null;
        boolean enabled = false;
        // When / Then
        assertThrows(NullPointerException.class, () -> new HttpProxyExclusion(host, enabled));
    }

    @Test
    void shouldCreateWithOtherInstance() {
        // Given
        Pattern host = Pattern.compile("example.org");
        boolean enabled = false;
        HttpProxyExclusion other = new HttpProxyExclusion(host, enabled);
        // When
        HttpProxyExclusion exclusion = new HttpProxyExclusion(other);
        // Then
        assertThat(exclusion.getHost(), is(equalTo(host)));
        assertThat(exclusion.isEnabled(), is(equalTo(enabled)));
    }

    @Test
    void shouldThrowWhenCreatingWithNullOtherInstance() {
        // Given
        HttpProxyExclusion other = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> new HttpProxyExclusion(other));
    }

    @Test
    void shouldSetEnabledState() {
        // Given
        Pattern host = Pattern.compile("example.org");
        HttpProxyExclusion exclusion = new HttpProxyExclusion(host, true);
        boolean enabled = false;
        // When
        exclusion.setEnabled(enabled);
        // Then
        assertThat(exclusion.isEnabled(), is(equalTo(enabled)));
    }

    @Test
    void shouldSetHost() {
        // Given
        HttpProxyExclusion exclusion = new HttpProxyExclusion(Pattern.compile("example.org"), true);
        Pattern host = Pattern.compile("example.com");
        // When
        exclusion.setHost(host);
        // Then
        assertThat(exclusion.getHost(), is(equalTo(host)));
    }

    @Test
    void shouldThrowWhenSettingNullHost() {
        // Given
        HttpProxyExclusion exclusion = new HttpProxyExclusion(Pattern.compile("example.org"), true);
        Pattern host = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> exclusion.setHost(host));
    }

    @Test
    void shouldProduceConsistentHashCodes() {
        // Given
        HttpProxyExclusion exclusion =
                new HttpProxyExclusion(Pattern.compile("example.org"), false);
        // When
        int hashCode = exclusion.hashCode();
        // Then
        assertThat(hashCode, is(equalTo(-1943962101)));
    }

    @Test
    void shouldBeEqualToItself() {
        // Given
        HttpProxyExclusion exclusion =
                new HttpProxyExclusion(Pattern.compile("example.org"), false);
        // When
        boolean equals = exclusion.equals(exclusion);
        // Then
        assertThat(equals, is(equalTo(true)));
    }

    static Stream<Arguments> constructorArgsProvider() {
        return Stream.of(
                arguments(Pattern.compile("example.org"), false),
                arguments(Pattern.compile("example.com"), true));
    }

    @ParameterizedTest
    @MethodSource("constructorArgsProvider")
    void shouldBeEqualToDifferentHttpProxyExclusionWithSameContents(Pattern host, boolean enabled) {
        // Given
        HttpProxyExclusion exclusion = new HttpProxyExclusion(host, enabled);
        HttpProxyExclusion otherEqualHttpProxyExclusion = new HttpProxyExclusion(host, enabled);
        // When
        boolean equals = exclusion.equals(otherEqualHttpProxyExclusion);
        // Then
        assertThat(equals, is(equalTo(true)));
    }

    @Test
    void shouldNotBeEqualToNull() {
        // Given
        HttpProxyExclusion exclusion =
                new HttpProxyExclusion(Pattern.compile("example.org"), false);
        // When
        boolean equals = exclusion.equals(null);
        // Then
        assertThat(equals, is(equalTo(false)));
    }

    static Stream<Arguments> differencesProvider() {
        Pattern host = Pattern.compile("example.org");
        Pattern otherHost = Pattern.compile("example.com");
        return Stream.of(
                arguments(host, false, host, true),
                arguments(host, true, host, false),
                arguments(host, true, otherHost, true),
                arguments(otherHost, true, host, true));
    }

    @ParameterizedTest
    @MethodSource("differencesProvider")
    void shouldNotBeEqualToHttpProxyExclusionWithDifferentValues(
            Pattern host, boolean enabled, Pattern otherHost, boolean otherEnabled) {
        // Given
        HttpProxyExclusion exclusion = new HttpProxyExclusion(host, enabled);
        HttpProxyExclusion otherHttpProxyExclusion =
                new HttpProxyExclusion(otherHost, otherEnabled);
        // When
        boolean equals = exclusion.equals(otherHttpProxyExclusion);
        // Then
        assertThat(equals, is(equalTo(false)));
    }

    @Test
    void shouldNotBeEqualToExtendedHttpProxyExclusion() {
        // Given
        HttpProxyExclusion exclusion =
                new HttpProxyExclusion(Pattern.compile("example.org"), false);
        HttpProxyExclusion otherHttpProxyExclusion =
                new HttpProxyExclusion(Pattern.compile("example.org"), false) {
                    // Anonymous HttpProxyExclusion
                };
        // When
        boolean equals = exclusion.equals(otherHttpProxyExclusion);
        // Then
        assertThat(equals, is(equalTo(false)));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "example.org",
                "subdomain.example.org",
                "example.org:443",
                "example.org:8080"
            })
    void shouldReturnTrueWhenTestingWithMatchingHost(String host) {
        // Given
        HttpProxyExclusion exclusion = new HttpProxyExclusion(Pattern.compile("example.org"), true);
        // When
        boolean result = exclusion.test(host);
        // Then
        assertThat(result, is(equalTo(true)));
    }

    @Test
    void shouldReturnFalseWhenTestingWithMatchingHostButNotEnabled() {
        // Given
        boolean enabled = false;
        HttpProxyExclusion exclusion =
                new HttpProxyExclusion(Pattern.compile("example.org"), enabled);
        // When
        boolean result = exclusion.test("subdomain.example.org");
        // Then
        assertThat(result, is(equalTo(false)));
    }

    @Test
    void shouldReturnFalseWhenTestingWithNonMatchingHost() {
        // Given
        HttpProxyExclusion exclusion = new HttpProxyExclusion(Pattern.compile("example.org"), true);
        // When
        boolean result = exclusion.test("example.com");
        // Then
        assertThat(result, is(equalTo(false)));
    }

    @Test
    void shouldCreateHostPattern() {
        // Given
        String value = "example.org";
        // When
        Pattern host = HttpProxyExclusion.createHostPattern(value);
        // Then
        assertThat(host, is(notNullValue()));
        assertThat(host.pattern(), is(equalTo(value)));
    }

    @ParameterizedTest
    @NullAndEmptySource
    void shouldReturnNullForEmptyAndNullHostPattern(String value) {
        // Given / When
        Pattern host = HttpProxyExclusion.createHostPattern(value);
        // Then
        assertThat(host, is(nullValue()));
    }

    @Test
    void shouldThrowWhenCreatingWithInvalidHostPattern() {
        // Given
        String value = "[";
        // When / Then
        assertThrows(
                IllegalArgumentException.class, () -> HttpProxyExclusion.createHostPattern(value));
    }
}
