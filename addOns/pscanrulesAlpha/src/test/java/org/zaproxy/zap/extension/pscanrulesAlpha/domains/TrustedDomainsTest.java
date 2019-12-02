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
package org.zaproxy.zap.extension.pscanrulesAlpha.domains;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;

public class TrustedDomainsTest {
    private TrustedDomains trustedDomains;

    @Before
    public void setUp() {
        trustedDomains = new TrustedDomains();
    }

    @Test
    public void shouldBeIncludedForPath() {
        // Given
        trustedDomains.update("https://www.example2.com/.*");

        // When
        boolean included = trustedDomains.isIncluded("https://www.example2.com/page1");

        // Then
        assertTrue(included);
    }

    @Test
    public void shouldNotBeIncludedForDifferentDomain() {
        // Given
        trustedDomains.update("https://www.example2.com/.*");

        // When
        boolean included = trustedDomains.isIncluded("https://www.example3.com/page1");

        // Then
        assertFalse(included);
    }

    @Test
    public void shouldNotBeIncludedForAnInvalidRegex() {
        // Given
        trustedDomains.update("[");

        // When
        boolean included = trustedDomains.isIncluded("https://www.example2.com/page1");

        // Then
        assertFalse(included);
    }
}
