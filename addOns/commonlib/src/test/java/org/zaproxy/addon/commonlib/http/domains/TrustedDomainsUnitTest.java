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
package org.zaproxy.addon.commonlib.http.domains;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class TrustedDomainsUnitTest {
    private TrustedDomains trustedDomains;

    @BeforeEach
    void setup() {
        trustedDomains = new TrustedDomains();
    }

    @Test
    void shouldBeIncludedForPath() {
        // Given
        trustedDomains.update("https://www.example2.com/.*");
        // When
        boolean included = trustedDomains.isIncluded("https://www.example2.com/page1");
        // Then
        assertTrue(included);
    }

    @Test
    void shouldNotBeIncludedForDifferentDomain() {
        // Given
        trustedDomains.update("https://www.example2.com/.*");
        // When
        boolean included = trustedDomains.isIncluded("https://www.example3.com/page1");
        // Then
        assertFalse(included);
    }

    @Test
    void shouldNotBeIncludedForAnInvalidRegex() {
        // Given
        trustedDomains.update("[");
        // When
        boolean included = trustedDomains.isIncluded("https://www.example2.com/page1");
        // Then
        assertFalse(included);
    }
}
