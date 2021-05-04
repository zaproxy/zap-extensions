/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.openapi.converter.swagger;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

/** Unit test for {@link InvalidUrlException}. */
class InvalidUrlExceptionUnitTest {

    @Test
    void shouldFailToCreateException2ArgWithNullUrl() {
        // Given
        String url = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> new InvalidUrlException(url, null));
    }

    @Test
    void shouldCreateException2ArgWithNonNullUrl() {
        // Given
        String url = "url";
        // When
        InvalidUrlException iue = new InvalidUrlException(url, null);
        // Then
        assertThat(iue.getUrl(), is(equalTo(url)));
    }

    @Test
    void shouldFailToCreateException3ArgWithNullUrl() {
        // Given
        String url = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> new InvalidUrlException(url, null, null));
    }

    @Test
    void shouldCreateException3ArgWithNonNullUrl() {
        // Given
        String url = "url";
        // When
        InvalidUrlException iue = new InvalidUrlException(url, null, null);
        // Then
        assertThat(iue.getUrl(), is(equalTo(url)));
    }
}
