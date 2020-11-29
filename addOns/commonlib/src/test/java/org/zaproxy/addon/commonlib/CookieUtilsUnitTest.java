/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.addon.commonlib;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

/** Unit test for {@link CookieUtils}. */
public class CookieUtilsUnitTest {

    private static final String EMPTY_HEADER_VALUE = "";
    private static final String EMPTY_ATTRIBUTE_NAME = "";

    @Test
    public void shouldFailToCheckNullHeaderValue() {
        // Given
        String headerValue = null;
        // When / Then
        assertThrows(
                IllegalArgumentException.class,
                () -> CookieUtils.hasAttribute(headerValue, EMPTY_ATTRIBUTE_NAME));
    }

    @Test
    public void shouldFailToCheckNullAttributeName() {
        // Given
        String attributeName = null;
        // When / Then
        assertThrows(
                IllegalArgumentException.class,
                () -> CookieUtils.hasAttribute(EMPTY_HEADER_VALUE, attributeName));
    }

    @Test
    public void shouldNotFindEmptyAttribute() {
        // Given
        String headerValue = "Name=Value; Attribute1; Attribute2=AV2; ;;";
        // When
        boolean found = CookieUtils.hasAttribute(headerValue, EMPTY_ATTRIBUTE_NAME);
        // Then
        assertThat(found, is(equalTo(false)));
    }

    @Test
    public void shouldNotFindAttributeInEmptyHeader() {
        // Given
        String attribute = "Attribute1";
        // When
        boolean found = CookieUtils.hasAttribute(EMPTY_HEADER_VALUE, attribute);
        // Then
        assertThat(found, is(equalTo(false)));
    }

    @Test
    public void shouldNotFindAttributeIfHeaderHasNoAttributes() {
        // Given
        String headerValue = "Name=Value";
        String attribute = "Attribute1";
        // When
        boolean found = CookieUtils.hasAttribute(headerValue, attribute);
        // Then
        assertThat(found, is(equalTo(false)));
    }

    @Test
    public void shouldNotFindAttributeInNamelessCookie() {
        // Given
        String headerValue = "=Value; Attribute1; Attribute2=AV2; ;;";
        String attribute = "Attribute1";
        // When
        boolean found = CookieUtils.hasAttribute(headerValue, attribute);
        // Then
        assertThat(found, is(equalTo(false)));
    }

    @Test
    public void shouldNotFindAttributeIfCookieHasNoNameValueSepartor() {
        // Given
        String headerValue = "Name; Attribute1; Attribute2=AV2; ;;";
        String attribute = "Attribute1";
        // When
        boolean found = CookieUtils.hasAttribute(headerValue, attribute);
        // Then
        assertThat(found, is(equalTo(false)));
    }

    @Test
    public void shouldNotFindAttributeEvenIfCookieNameIsEqual() {
        // Given
        String headerValue = "Attribute1=Value; Attribute2=AV2";
        String attribute = "Attribute1";
        // When
        boolean found = CookieUtils.hasAttribute(headerValue, attribute);
        // Then
        assertThat(found, is(equalTo(false)));
    }

    @Test
    public void shouldNotFindAttributeEvenIfCookieValueIsEqual() {
        // Given
        String headerValue = "Name=Attribute1; Attribute2=AV2";
        String attribute = "Attribute1";
        // When
        boolean found = CookieUtils.hasAttribute(headerValue, attribute);
        // Then
        assertThat(found, is(equalTo(false)));
    }

    @Test
    public void shouldNotFindAttributeEvenIfAnAttributeValueIsEqual() {
        // Given
        String headerValue = "Name=Value; Attribute2=Attribute1";
        String attribute = "Attribute1";
        // When
        boolean found = CookieUtils.hasAttribute(headerValue, attribute);
        // Then
        assertThat(found, is(equalTo(false)));
    }

    @Test
    public void shouldFindAttributeInValidCookieHeader() {
        // Given
        String headerValue = "Cookie=Value; Attribute1; Attribute2=AV2";
        String attribute = "Attribute1";
        // When
        boolean found = CookieUtils.hasAttribute(headerValue, attribute);
        // Then
        assertThat(found, is(equalTo(true)));
    }

    @Test
    public void shouldFindAttributeEvenIfCookieHasNoValue() {
        // Given
        String headerValue = "Cookie=; Attribute1; Attribute2=AV2";
        String attribute = "Attribute1";
        // When
        boolean found = CookieUtils.hasAttribute(headerValue, attribute);
        // Then
        assertThat(found, is(equalTo(true)));
    }

    @Test
    public void shouldFindAttributeEvenIfItHasValue() {
        // Given
        String headerValue = "Cookie=Value; Attribute1; Attribute2=AV2";
        String attribute = "Attribute2";
        // When
        boolean found = CookieUtils.hasAttribute(headerValue, attribute);
        // Then
        assertThat(found, is(equalTo(true)));
    }

    @Test
    public void shouldFindAttributeEvenIfItHasSpacesInName() {
        // Given
        String headerValue = "Cookie=Value; Attribute1;  Attribute2  =AV2";
        String attribute = "Attribute2";
        // When
        boolean found = CookieUtils.hasAttribute(headerValue, attribute);
        // Then
        assertThat(found, is(equalTo(true)));
    }

    @Test
    public void shouldFindAttributeEvenIfItHasDifferentCase() {
        // Given
        String headerValue = "Cookie=Value; Attribute1; Attribute2=AV2";
        String attribute = "aTtRiBuTe2";
        // When
        boolean found = CookieUtils.hasAttribute(headerValue, attribute);
        // Then
        assertThat(found, is(equalTo(true)));
    }

    @Test
    public void shouldNotFindCookiePlusNameIfNameIsNull() {
        // Given
        String fullHeader = "Set-Cookie: foo; Attribute1";
        String headerValue = "foo; Attribute1";
        // When
        String name = CookieUtils.getSetCookiePlusName(fullHeader, headerValue);
        // Then
        assertThat(name, is(equalTo(null)));
    }

    @Test
    public void shouldKnowThatNameDoesNotIncludeSemiColon() {
        // Given
        String fullHeader = "Set-Cookie: foo; Attribute1; Attribute2=AV2";
        String headerValue = "foo; Attribute1; Attribute2=AV2";
        // When
        String name = CookieUtils.getSetCookiePlusName(fullHeader, headerValue);
        // Then
        assertThat(name, is(equalTo(null)));
    }

    @Test
    public void shouldFindCookiePlusNameIfWellFormed() {
        // Given
        String fullHeader = "Set-Cookie: name=value; Attribute1; Attribute2=AV2";
        String headerValue = "name=value; Attribute1; Attribute2=AV2";
        // When
        String name = CookieUtils.getSetCookiePlusName(fullHeader, headerValue);
        // Then
        assertThat(name, is(equalTo("Set-Cookie: name")));
    }
}
