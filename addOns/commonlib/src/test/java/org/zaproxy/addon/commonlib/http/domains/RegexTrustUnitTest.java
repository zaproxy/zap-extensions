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
package org.zaproxy.addon.commonlib.http.domains;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class RegexTrustUnitTest {

    @ParameterizedTest
    @ValueSource(strings = {"http.cat", "www.httpexample.com"})
    void shouldNotMatchDomainsEvenIfTheyIncludeSchemeLikeSubstrings(String candidate) {
        // Given / When
        boolean found = RegexTrust.SIMPLE_URL_REGEX.matcher(candidate).find();
        // Then
        assertFalse(found);
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://example.com", "https://www.httpexample.com"})
    void shouldMatchStringsThatStartWithSchemes(String candidate) {
        // Given / When
        boolean found = RegexTrust.SIMPLE_URL_REGEX.matcher(candidate).find();
        // Then
        assertTrue(found);
    }
}
