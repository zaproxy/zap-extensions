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
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.network.HttpRequestHeader;

/** Unit test for {@link PassThrough}. */
class PassThroughUnitTest {

    @Test
    void shouldCreateWithGivenValues() {
        // Given
        Pattern authority = Pattern.compile("example.org");
        boolean enabled = false;
        // When
        PassThrough passThrough = new PassThrough(authority, enabled);
        // Then
        assertThat(passThrough.getAuthority(), is(equalTo(authority)));
        assertThat(passThrough.isEnabled(), is(equalTo(enabled)));
    }

    @Test
    void shouldThrowWhenCreatingWithNullAuthority() {
        // Given
        Pattern authority = null;
        boolean enabled = false;
        // When / Then
        assertThrows(NullPointerException.class, () -> new PassThrough(authority, enabled));
    }

    @Test
    void shouldCreateWithOtherInstance() {
        // Given
        Pattern authority = Pattern.compile("example.org");
        boolean enabled = false;
        PassThrough other = new PassThrough(authority, enabled);
        // When
        PassThrough passThrough = new PassThrough(other);
        // Then
        assertThat(passThrough.getAuthority(), is(equalTo(authority)));
        assertThat(passThrough.isEnabled(), is(equalTo(enabled)));
    }

    @Test
    void shouldThrowWhenCreatingWithNullOtherInstance() {
        // Given
        PassThrough other = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> new PassThrough(other));
    }

    @Test
    void shouldSetEnabledState() {
        // Given
        Pattern authority = Pattern.compile("example.org");
        PassThrough passThrough = new PassThrough(authority, true);
        boolean enabled = false;
        // When
        passThrough.setEnabled(enabled);
        // Then
        assertThat(passThrough.isEnabled(), is(equalTo(enabled)));
    }

    @Test
    void shouldSetAuthority() {
        // Given
        PassThrough passThrough = new PassThrough(Pattern.compile("example.org"), true);
        Pattern authority = Pattern.compile("example.com");
        // When
        passThrough.setAuthority(authority);
        // Then
        assertThat(passThrough.getAuthority(), is(equalTo(authority)));
    }

    @Test
    void shouldThrowWhenSettingNullAuthority() {
        // Given
        PassThrough passThrough = new PassThrough(Pattern.compile("example.org"), true);
        Pattern authority = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> passThrough.setAuthority(authority));
    }

    @Test
    void shouldProduceConsistentHashCodes() {
        // Given
        PassThrough passThrough = new PassThrough(Pattern.compile("example.org"), false);
        // When
        int hashCode = passThrough.hashCode();
        // Then
        assertThat(hashCode, is(equalTo(-1943962101)));
    }

    @Test
    void shouldBeEqualToItself() {
        // Given
        PassThrough passThrough = new PassThrough(Pattern.compile("example.org"), false);
        // When
        boolean equals = passThrough.equals(passThrough);
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
    void shouldBeEqualToDifferentPassThroughWithSameContents(Pattern authority, boolean enabled) {
        // Given
        PassThrough passThrough = new PassThrough(authority, enabled);
        PassThrough otherEqualPassThrough = new PassThrough(authority, enabled);
        // When
        boolean equals = passThrough.equals(otherEqualPassThrough);
        // Then
        assertThat(equals, is(equalTo(true)));
    }

    @Test
    void shouldNotBeEqualToNull() {
        // Given
        PassThrough passThrough = new PassThrough(Pattern.compile("example.org"), false);
        // When
        boolean equals = passThrough.equals(null);
        // Then
        assertThat(equals, is(equalTo(false)));
    }

    static Stream<Arguments> differencesProvider() {
        Pattern authority = Pattern.compile("example.org");
        Pattern otherAuthority = Pattern.compile("example.com");
        return Stream.of(
                arguments(authority, false, authority, true),
                arguments(authority, true, authority, false),
                arguments(authority, true, otherAuthority, true),
                arguments(otherAuthority, true, authority, true));
    }

    @ParameterizedTest
    @MethodSource("differencesProvider")
    void shouldNotBeEqualToPassThroughWithDifferentValues(
            Pattern authority, boolean enabled, Pattern otherAuthority, boolean otherEnabled) {
        // Given
        PassThrough passThrough = new PassThrough(authority, enabled);
        PassThrough otherPassThrough = new PassThrough(otherAuthority, otherEnabled);
        // When
        boolean equals = passThrough.equals(otherPassThrough);
        // Then
        assertThat(equals, is(equalTo(false)));
    }

    @Test
    void shouldNotBeEqualToExtendedPassThrough() {
        // Given
        PassThrough passThrough = new PassThrough(Pattern.compile("example.org"), false);
        PassThrough otherPassThrough = new PassThrough(Pattern.compile("example.org"), false) {
                    // Anonymous PassThrough
                };
        // When
        boolean equals = passThrough.equals(otherPassThrough);
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
    void shouldReturnTrueWhenTestingWithMatchingAuthority(String authority) {
        // Given
        PassThrough passThrough = new PassThrough(Pattern.compile("example.org"), true);
        // When
        boolean result = passThrough.test(requestWithAuthority(authority));
        // Then
        assertThat(result, is(equalTo(true)));
    }

    @Test
    void shouldReturnFalseWhenTestingWithMatchingAuthorityButNotEnabled() {
        // Given
        boolean enabled = false;
        PassThrough passThrough = new PassThrough(Pattern.compile("example.org"), enabled);
        // When
        boolean result = passThrough.test(requestWithAuthority("subdomain.example.org"));
        // Then
        assertThat(result, is(equalTo(false)));
    }

    @Test
    void shouldReturnFalseWhenTestingWithNonMatchingAuthority() {
        // Given
        PassThrough passThrough = new PassThrough(Pattern.compile("example.org"), true);
        // When
        boolean result = passThrough.test(requestWithAuthority("example.com"));
        // Then
        assertThat(result, is(equalTo(false)));
    }

    @Test
    void shouldCreateAuthorityPattern() {
        // Given
        String value = "example.org";
        // When
        Pattern authority = PassThrough.createAuthorityPattern(value);
        // Then
        assertThat(authority, is(notNullValue()));
        assertThat(authority.pattern(), is(equalTo(value)));
    }

    @ParameterizedTest
    @NullAndEmptySource
    void shouldReturnNullForEmptyAndNullAuthorityPattern(String value) {
        // Given / When
        Pattern authority = PassThrough.createAuthorityPattern(value);
        // Then
        assertThat(authority, is(nullValue()));
    }

    @Test
    void shouldThrowWhenCreatingWithInvalidAuthorityPattern() {
        // Given
        String value = "[";
        // When / Then
        assertThrows(
                IllegalArgumentException.class, () -> PassThrough.createAuthorityPattern(value));
    }

    private static HttpRequestHeader requestWithAuthority(String authority) {
        HttpRequestHeader requestHeader = mock(HttpRequestHeader.class);
        URI uri = mock(URI.class);
        given(requestHeader.getURI()).willReturn(uri);
        given(uri.getEscapedAuthority()).willReturn(authority);
        return requestHeader;
    }
}
