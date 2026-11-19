/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrules;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.extension.pscanrules.KnownVulnerabilities.VersionRange;
import org.zaproxy.zap.extension.pscanrules.KnownVulnerabilities.Vulnerability;

class RubyAdvisoriesUnitTest {

    private static final ObjectMapper YAML = new ObjectMapper(new YAMLFactory());

    private static JsonNode advisory(String patched, String unaffected, String cvss)
            throws Exception {
        return YAML.readTree(
                """
                engine: ruby
                cve: 2026-41316
                ghsa: q339-8rmv-2mhv
                url: https://nvd.nist.gov/vuln/detail/CVE-2026-41316
                title: ERB has an @_init deserialization guard bypass via
                  def_module
                date: 2026-04-21
                description: |
                  ERB implements an @_init guard to prevent code execution when ERB
                  objects are reconstructed via Marshal.load on untrusted data.
                %s
                patched_versions: %s
                unaffected_versions: %s
                related:
                  url:
                    - https://nvd.nist.gov/vuln/detail/CVE-2026-41316
                    - https://www.ruby-lang.org/en/news/2026/04/21/erb/
                    - http://example.com/not-https
                """
                        .formatted(cvss, patched, unaffected));
    }

    private static Vulnerability convert(String patched, String unaffected, String cvss)
            throws Exception {
        return RubyAdvisories.toVulnerability(advisory(patched, unaffected, cvss)).orElseThrow();
    }

    @Test
    void shouldConvertAdvisory() throws Exception {
        // Given / When
        Vulnerability vulnerability =
                convert("['~> 3.3.12', '~> 3.4.10', '>= 4.0.3']", "[]", "cvss_v3: 8.1");
        // Then
        assertThat(vulnerability.cve(), is("CVE-2026-41316"));
        assertThat(vulnerability.ghsa(), is("q339-8rmv-2mhv"));
        assertThat(
                vulnerability.name(),
                is("ERB has an @_init deserialization guard bypass via def_module"));
        assertThat(vulnerability.severity(), is("high"));
        assertThat(vulnerability.cvss(), is(8.1));
        assertThat(vulnerability.published(), is("2026-04-21"));
        assertThat(vulnerability.source(), is(RubyAdvisories.SOURCE_GENERATED));
        assertThat(
                vulnerability.description(),
                is(
                        "ERB implements an @_init guard to prevent code execution when ERB objects are reconstructed via Marshal.load on untrusted data."));
        assertThat(
                vulnerability.links(),
                contains(
                        "https://nvd.nist.gov/vuln/detail/CVE-2026-41316",
                        "https://www.ruby-lang.org/en/news/2026/04/21/erb/"));
        assertThat(
                vulnerability.affected(),
                contains(
                        new VersionRange("0.0.0", "3.3.12", true),
                        new VersionRange("3.4.0", "3.4.10", false),
                        new VersionRange("3.5.0", "4.0.3", false)));
    }

    @Test
    void shouldUseUnaffectedVersionsAsLowerBound() throws Exception {
        // Given / When
        Vulnerability vulnerability = convert("['>= 2.3.1']", "['< 2.2.2']", "cvss_v3: 9.8");
        // Then
        assertThat(vulnerability.severity(), is("critical"));
        assertThat(vulnerability.affected(), contains(new VersionRange("2.2.2", "2.3.1", false)));
    }

    @Test
    void shouldTakeUnaffectedLinesOutOfTheRange() throws Exception {
        // Given / When
        Vulnerability vulnerability =
                convert("['~> 3.0.4', '>= 3.1.2']", "['~> 2.6.0', '~> 2.7.0']", "cvss_v3: 9.8");
        // Then
        assertThat(
                vulnerability.affected(),
                contains(
                        new VersionRange("0.0.0", "2.6.0", true),
                        new VersionRange("2.8.0", "3.0.4", false),
                        new VersionRange("3.1.0", "3.1.2", false)));
    }

    @Test
    void shouldAssumeReleasesListedByPatchLevelAreAffected() throws Exception {
        // Given / When
        Vulnerability vulnerability = convert("['~> 1.8.7.72', '>= 1.9.0']", "[]", "cvss_v2: 5.0");
        // Then
        assertThat(vulnerability.severity(), is("medium"));
        assertThat(vulnerability.cvss(), is(5.0));
        assertThat(vulnerability.affected(), contains(new VersionRange("0.0.0", "1.9.0", true)));
    }

    @Test
    void shouldIgnorePreReleaseAndPatchLevelSuffixes() throws Exception {
        // Given / When
        Vulnerability vulnerability =
                convert("['~> 2.4.8', '> 2.7.0-preview1', '~> 2.5.1']", "[]", "cvss_v3: 5.3");
        // Then
        assertThat(
                vulnerability.affected(),
                contains(
                        new VersionRange("0.0.0", "2.4.8", true),
                        new VersionRange("2.5.0", "2.5.1", false),
                        new VersionRange("2.6.0", "2.7.0", false)));
    }

    @Test
    void shouldNotReportReleasesAfterTheLastOneListed() throws Exception {
        // Given / When
        Vulnerability vulnerability = convert("['~> 3.3.10']", "[]", "cvss_v3: 5.3");
        // Then
        assertThat(vulnerability.affected(), contains(new VersionRange("0.0.0", "3.3.10", true)));
    }

    @Test
    void shouldAssumeMediumSeverityWithoutCvss() throws Exception {
        // Given / When
        Vulnerability vulnerability = convert("['>= 3.4.7']", "[]", "");
        // Then
        assertThat(vulnerability.severity(), is("medium"));
        assertThat(vulnerability.cvss(), is(nullValue()));
    }

    @Test
    void shouldFailOnUnexpectedVersion() {
        // Given / When
        IllegalArgumentException e =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> convert("['== 3.4.7']", "[]", "cvss_v3: 5.3"));
        // Then
        assertThat(e.getMessage(), is("CVE-2026-41316: unexpected version == 3.4.7"));
    }

    @Test
    void shouldFailOnAdvisoryWithoutVersions() {
        // Given / When
        IllegalArgumentException e =
                assertThrows(
                        IllegalArgumentException.class, () -> convert("[]", "[]", "cvss_v3: 5.3"));
        // Then
        assertThat(e.getMessage(), is("CVE-2026-41316: no patched or unaffected versions"));
    }

    @Test
    void shouldFailOnAdvisoryWithoutCve() throws Exception {
        // Given
        JsonNode advisory =
                YAML.readTree("engine: ruby\ntitle: No CVE\npatched_versions: ['>= 3.0.0']\n");
        // When / Then
        assertThrows(
                IllegalArgumentException.class, () -> RubyAdvisories.toVulnerability(advisory));
    }

    @Test
    void shouldSkipAdvisoryOfAnotherEngine() throws Exception {
        // Given
        JsonNode advisory =
                YAML.readTree(
                        "engine: jruby\ncve: 2020-1234\ntitle: JRuby\npatched_versions: ['>= 9.2.0']\n");
        // When / Then
        assertThat(RubyAdvisories.toVulnerability(advisory).isPresent(), is(false));
    }
}
