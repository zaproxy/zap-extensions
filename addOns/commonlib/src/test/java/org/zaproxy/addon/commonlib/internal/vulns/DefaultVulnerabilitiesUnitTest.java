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
package org.zaproxy.addon.commonlib.internal.vulns;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.emptyString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;

import java.util.Locale;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerability;

/** Unit test for {@link DefaultVulnerabilities}. */
class DefaultVulnerabilitiesUnitTest {

    @Test
    void shouldLoadDefaultVulnerabilities() {
        // Given
        Locale locale = Locale.ROOT;
        // When
        DefaultVulnerabilities vulnerabilities = new DefaultVulnerabilities(locale);
        // Then
        assertDefaults(vulnerabilities);
    }

    private static void assertDefaults(DefaultVulnerabilities vulnerabilities) {
        assertThat(vulnerabilities.getAll(), hasSize(52));
        assertVulnerability(vulnerabilities.get("wasc_1"), 1, 3);
        assertVulnerability(vulnerabilities.get("wasc_13"), 13, 1);
        assertVulnerability(vulnerabilities.get("wasc_49"), 49, 3);
    }

    private static void assertVulnerability(
            Vulnerability vulnerability, int id, int numberOfReferences) {
        assertThat(vulnerability, is(notNullValue()));
        assertThat(vulnerability.getWascId(), is(equalTo(id)));
        assertThat(vulnerability.getName(), is(not(emptyString())));
        assertThat(vulnerability.getDescription(), is(not(emptyString())));
        assertThat(vulnerability.getSolution(), is(not(emptyString())));
        assertThat(vulnerability.getReferences(), hasSize(numberOfReferences));
    }

    @Test
    void shouldLoadDefaultVulnerabilitiesForUnknownLocale() {
        // Given
        Locale locale =
                new Locale.Builder().setLanguage("XX").setRegion("YY").setScript("ZZZZ").build();
        // When
        DefaultVulnerabilities vulnerabilities = new DefaultVulnerabilities(locale);
        // Then
        assertDefaults(vulnerabilities);
    }
}
