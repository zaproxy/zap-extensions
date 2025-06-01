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
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

import java.io.InputStream;
import java.util.List;
import java.util.Locale;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.model.Vulnerability;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link LegacyVulnerabilitiesLoader}. */
@SuppressWarnings("removal")
class LegacyVulnerabilitiesLoaderUnitTest extends TestUtils {

    private static final String DEFAULT_FILE_NAME = "vulnerabilities";

    private static final String TEST_FILE_NAME = DEFAULT_FILE_NAME + "-test";

    private Function<String, InputStream> inputStreamProvider =
            LegacyVulnerabilitiesLoaderUnitTest.class::getResourceAsStream;

    private List<Vulnerability> load(Locale locale) {
        return LegacyVulnerabilitiesLoader.load(
                locale,
                name ->
                        inputStreamProvider.apply(
                                TEST_FILE_NAME + name.substring(DEFAULT_FILE_NAME.length())));
    }

    @Test
    void shouldReturnEmptyListIfVulnerabilitiesNotFound() {
        // Given
        inputStreamProvider = name -> null;
        // When
        List<Vulnerability> vulnerabilities = load(Locale.ROOT);
        // Then
        assertThat(vulnerabilities, is(empty()));
    }

    @Test
    void shouldReturnListWithVulnerabilitiesForDefaultLocale() {
        // Given / When
        List<Vulnerability> vulnerabilities = load(Locale.ROOT);
        // Then
        assertThat(vulnerabilities.size(), is(equalTo(2)));

        Vulnerability wasc1 = vulnerabilities.get(0);
        assertThat(wasc1.getWascId(), is(equalTo(1)));
        assertThat(wasc1.getAlert(), is(equalTo("Locale default")));
        assertThat(wasc1.getDescription(), is(equalTo("Description default")));
        assertThat(wasc1.getSolution(), is(equalTo("Solution default")));
        assertThat(wasc1.getReferences().size(), is(equalTo(2)));
        assertThat(wasc1.getReferences().get(0), is(equalTo("Reference default 1")));
        assertThat(wasc1.getReferences().get(1), is(equalTo("Reference default 2")));

        Vulnerability wasc2 = vulnerabilities.get(1);
        assertThat(wasc2.getWascId(), is(equalTo(2)));
        assertThat(wasc2.getAlert(), is(equalTo("Alert 2")));
        assertThat(wasc2.getDescription(), is(equalTo("Description 2")));
        assertThat(wasc2.getSolution(), is(equalTo("Solution 2")));
        assertThat(wasc2.getReferences().size(), is(equalTo(1)));
        assertThat(wasc2.getReferences().get(0), is(equalTo("Reference 2")));
    }

    @Test
    void shouldLoadFileWithSameLanguageCountryWhenAvailable() {
        // Given
        Locale locale = new Locale.Builder().setLanguage("nl").setRegion("NL").build();
        // When
        List<Vulnerability> vulnerabilities = load(locale);
        // Then
        assertThat(vulnerabilities, is(not(empty())));
        assertThat(vulnerabilities.get(0).getAlert(), is(equalTo("Locale nl_NL")));
    }

    @Test
    void shouldLoadDefaultFileEvenIfFileWithSameLanguageButDifferentCountryIsAvailable() {
        // Given
        Locale.setDefault(new Locale.Builder().setLanguage("nl").setRegion("XX").build());
        Locale locale = new Locale.Builder().setLanguage("nl").setRegion("XX").build();
        // When
        List<Vulnerability> vulnerabilities = load(locale);
        // Then
        assertThat(vulnerabilities, is(not(empty())));
        assertThat(vulnerabilities.get(0).getAlert(), is(equalTo("Locale default")));
    }

    @Test
    void shouldLoadFileWithOnlyLanguageMatchWhenLanguageCountryNotAvailable() {
        // Given
        Locale locale = new Locale.Builder().setLanguage("es").setRegion("AR").build();
        // When
        List<Vulnerability> vulnerabilities = load(locale);
        // Then
        assertThat(vulnerabilities, is(not(empty())));
        assertThat(vulnerabilities.get(0).getAlert(), is(equalTo("Locale es")));
    }

    @Test
    void shouldReturnEmptyListIfFoundFileIsEmpty() {
        // Given
        inputStreamProvider = name -> invalidVulnerabilities("empty");
        // When
        List<Vulnerability> vulnerabilities = load(Locale.ROOT);
        // Then
        assertThat(vulnerabilities, is(empty()));
    }

    private static InputStream invalidVulnerabilities(String suffix) {
        return LegacyVulnerabilitiesLoaderUnitTest.class.getResourceAsStream(
                "invalid/" + TEST_FILE_NAME + "-" + suffix + ".xml");
    }

    @Test
    void shouldReturnEmptyListIfFoundFileIsNotValidXml() {
        // Given
        inputStreamProvider = name -> invalidVulnerabilities("invalid-xml");
        // When
        List<Vulnerability> vulnerabilities = load(Locale.ROOT);
        // Then
        assertThat(vulnerabilities, is(empty()));
    }
}
