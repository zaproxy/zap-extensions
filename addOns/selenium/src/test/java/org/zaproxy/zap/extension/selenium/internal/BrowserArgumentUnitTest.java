/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.zap.extension.selenium.internal;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/** Unit test for {@link BrowserArgument}. */
class BrowserArgumentUnitTest {

    @Test
    void shouldCreateWithGivenValues() {
        // Given
        String argument = "--arg";
        boolean enabled = false;
        // When
        BrowserArgument browserArgument = new BrowserArgument(argument, enabled);
        // Then
        assertThat(browserArgument.getArgument(), is(equalTo(argument)));
        assertThat(browserArgument.isEnabled(), is(equalTo(enabled)));
    }

    @Test
    void shouldThrowWhenCreatingWithNullArgument() {
        // Given
        String argument = null;
        boolean enabled = false;
        // When / Then
        assertThrows(NullPointerException.class, () -> new BrowserArgument(argument, enabled));
    }

    @Test
    void shouldCreateWithOtherInstance() {
        // Given
        String argument = "--arg";
        boolean enabled = false;
        BrowserArgument other = new BrowserArgument(argument, enabled);
        // When
        BrowserArgument browserArgument = new BrowserArgument(other);
        // Then
        assertThat(browserArgument.getArgument(), is(equalTo(argument)));
        assertThat(browserArgument.isEnabled(), is(equalTo(enabled)));
    }

    @Test
    void shouldThrowWhenCreatingWithNullOtherInstance() {
        // Given
        BrowserArgument other = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> new BrowserArgument(other));
    }

    @Test
    void shouldSetEnabledState() {
        // Given
        String argument = "--arg";
        BrowserArgument browserArgument = new BrowserArgument(argument, true);
        boolean enabled = false;
        // When
        browserArgument.setEnabled(enabled);
        // Then
        assertThat(browserArgument.isEnabled(), is(equalTo(enabled)));
    }

    @Test
    void shouldSetArgument() {
        // Given
        BrowserArgument browserArgument = new BrowserArgument("--arg", true);
        String argument = "--other-arg";
        // When
        browserArgument.setArgument(argument);
        // Then
        assertThat(browserArgument.getArgument(), is(equalTo(argument)));
    }

    @Test
    void shouldSetArgumentTrimmed() {
        // Given
        BrowserArgument browserArgument = new BrowserArgument("--arg", true);
        String argument = "--other-arg";
        // When
        browserArgument.setArgument("  " + argument + "\t");
        // Then
        assertThat(browserArgument.getArgument(), is(equalTo(argument)));
    }

    @Test
    void shouldThrowWhenSettingNullArgument() {
        // Given
        BrowserArgument browserArgument = new BrowserArgument("--arg", true);
        String argument = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> browserArgument.setArgument(argument));
    }

    @Test
    void shouldProduceConsistentHashCodes() {
        // Given
        BrowserArgument browserArgument = new BrowserArgument("--arg", false);
        // When
        int hashCode = browserArgument.hashCode();
        // Then
        assertThat(hashCode, is(equalTo(1332874912)));
    }

    @Test
    void shouldBeEqualToItself() {
        // Given
        BrowserArgument browserArgument = new BrowserArgument("--arg", false);
        // When
        boolean equals = browserArgument.equals(browserArgument);
        // Then
        assertThat(equals, is(equalTo(true)));
    }

    static Stream<Arguments> constructorArgsProvider() {
        return Stream.of(arguments("--arg", false), arguments("--other-arg", true));
    }

    @ParameterizedTest
    @MethodSource("constructorArgsProvider")
    void shouldBeEqualToDifferentBrowserArgumentWithSameContents(String argument, boolean enabled) {
        // Given
        BrowserArgument browserArgument = new BrowserArgument(argument, enabled);
        BrowserArgument otherEqualBrowserArgument = new BrowserArgument(argument, enabled);
        // When
        boolean equals = browserArgument.equals(otherEqualBrowserArgument);
        // Then
        assertThat(equals, is(equalTo(true)));
    }

    @Test
    void shouldNotBeEqualToNull() {
        // Given
        BrowserArgument browserArgument = new BrowserArgument("--arg", false);
        // When
        boolean equals = browserArgument.equals(null);
        // Then
        assertThat(equals, is(equalTo(false)));
    }

    static Stream<Arguments> differencesProvider() {
        String argument = "--arg";
        String otherArgument = "--other-arg";
        return Stream.of(
                arguments(argument, false, argument, true),
                arguments(argument, true, argument, false),
                arguments(argument, true, otherArgument, true),
                arguments(otherArgument, true, argument, true));
    }

    @ParameterizedTest
    @MethodSource("differencesProvider")
    void shouldNotBeEqualToBrowserArgumentWithDifferentValues(
            String argument, boolean enabled, String otherArgument, boolean otherEnabled) {
        // Given
        BrowserArgument browserArgument = new BrowserArgument(argument, enabled);
        BrowserArgument otherBrowserArgument = new BrowserArgument(otherArgument, otherEnabled);
        // When
        boolean equals = browserArgument.equals(otherBrowserArgument);
        // Then
        assertThat(equals, is(equalTo(false)));
    }

    @Test
    void shouldBeEqualToExtendedBrowserArgumentWithSameValues() {
        // Given
        BrowserArgument browserArgument = new BrowserArgument("--arg", false);
        BrowserArgument otherBrowserArgument = new BrowserArgument("--arg", false) {
                    // Anonymous BrowserArgument
                };
        // When
        boolean equals = browserArgument.equals(otherBrowserArgument);
        // Then
        assertThat(equals, is(equalTo(true)));
    }
}
