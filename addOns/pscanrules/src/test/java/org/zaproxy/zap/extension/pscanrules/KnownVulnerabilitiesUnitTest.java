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
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.lessThan;
import static org.hamcrest.Matchers.matchesPattern;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.startsWith;

import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.zap.extension.pscanrules.KnownVulnerabilities.Severity;
import org.zaproxy.zap.extension.pscanrules.KnownVulnerabilities.VersionRange;
import org.zaproxy.zap.extension.pscanrules.KnownVulnerabilities.Vulnerability;

class KnownVulnerabilitiesUnitTest {

    @TempDir Path tempDir;

    @Test
    void shouldHaveKnownVulnerabilitiesFile() {
        // Given / When
        URL url =
                getClass()
                        .getResource(ServerSideVersionScanRule.PHP_KNOWN_VULNERABILITIES_RESOURCE);
        // Then
        assertThat(url, is(notNullValue()));
    }

    @Test
    void shouldLoadBundledFile() throws Exception {
        // Given
        Path path =
                Paths.get(
                        getClass()
                                .getResource(
                                        ServerSideVersionScanRule
                                                .PHP_KNOWN_VULNERABILITIES_RESOURCE)
                                .toURI());
        // When
        KnownVulnerabilities known = KnownVulnerabilities.load(path);
        // Then
        assertThat(known.vulnerabilities().size(), is(greaterThan(0)));
        for (Vulnerability vulnerability : known.vulnerabilities()) {
            assertThat(vulnerability.cve(), startsWith("CVE-"));
            assertThat(vulnerability.name(), is(notNullValue()));
            assertThat(vulnerability.description(), is(notNullValue()));
            assertThat(vulnerability.severity(), is(notNullValue()));
            assertThat(vulnerability.affected(), is(not(empty())));
            assertThat(vulnerability.links(), is(not(empty())));
        }
    }

    @Test
    void shouldHaveValidNonOverlappingRangesInBundledFile() throws Exception {
        // Given
        Path path =
                Paths.get(
                        getClass()
                                .getResource(
                                        ServerSideVersionScanRule
                                                .PHP_KNOWN_VULNERABILITIES_RESOURCE)
                                .toURI());
        // When
        KnownVulnerabilities known = KnownVulnerabilities.load(path);
        // Then
        for (Vulnerability vulnerability : known.vulnerabilities()) {
            List<VersionRange> ranges =
                    vulnerability.affected().stream()
                            .sorted(
                                    (a, b) ->
                                            KnownVulnerabilities.compareVersions(
                                                    a.introduced(), b.introduced()))
                            .toList();
            for (int i = 0; i < ranges.size(); i++) {
                VersionRange range = ranges.get(i);
                assertThat(
                        vulnerability.cve(), range.introduced(), matchesPattern("\\d+(\\.\\d+)*"));
                if (range.fixed() != null) {
                    assertThat(
                            vulnerability.cve(), range.fixed(), matchesPattern("\\d+(\\.\\d+)*"));
                    assertThat(
                            vulnerability.cve(),
                            KnownVulnerabilities.compareVersions(range.introduced(), range.fixed()),
                            is(lessThan(0)));
                }
                if (i > 0) {
                    VersionRange previous = ranges.get(i - 1);
                    assertThat(
                            vulnerability.cve() + " ranges overlap",
                            previous.fixed() != null
                                    && KnownVulnerabilities.compareVersions(
                                                    previous.fixed(), range.introduced())
                                            <= 0,
                            is(true));
                }
            }
        }
    }

    @Test
    void shouldLoadBundledResource() {
        // Given / When
        KnownVulnerabilities known =
                KnownVulnerabilities.loadResource(
                        ServerSideVersionScanRule.PHP_KNOWN_VULNERABILITIES_RESOURCE);
        // Then
        assertThat(known.vulnerabilities().size(), is(greaterThan(0)));
    }

    @Test
    void shouldReturnEmptyWhenResourceDoesNotExist() {
        // Given / When
        KnownVulnerabilities known = KnownVulnerabilities.loadResource("/missing.json");
        // Then
        assertThat(known.vulnerabilities(), is(empty()));
    }

    @Test
    void shouldReturnEmptyWhenFileDoesNotExist() {
        // Given / When
        KnownVulnerabilities known = KnownVulnerabilities.load(tempDir.resolve("missing.json"));
        // Then
        assertThat(known.vulnerabilities(), is(empty()));
    }

    @Test
    void shouldReturnEmptyWhenFileIsNotValidJson() throws Exception {
        // Given
        Path path = Files.writeString(tempDir.resolve("bad.json"), "{ not json");
        // When
        KnownVulnerabilities known = KnownVulnerabilities.load(path);
        // Then
        assertThat(known.vulnerabilities(), is(empty()));
    }

    @Test
    void shouldIgnoreUnknownFields() throws Exception {
        // Given
        Path path =
                Files.writeString(
                        tempDir.resolve("extra.json"),
                        """
                        {
                          "_comment": "ignored",
                          "schemaVersion": 1,
                          "vulnerabilities": [
                            {
                              "cve": "CVE-2024-0001",
                              "name": "Test",
                              "description": "Desc",
                              "severity": "high",
                              "cvss": 7.5,
                              "extra": true,
                              "affected": [ { "introduced": "8.1.0", "fixed": "8.1.5", "note": "x" } ],
                              "links": [ "https://example.com" ]
                            }
                          ]
                        }
                        """);
        // When
        KnownVulnerabilities known = KnownVulnerabilities.load(path);
        // Then
        assertThat(known.vulnerabilities().size(), is(1));
        assertThat(known.vulnerabilities().get(0).cve(), is("CVE-2024-0001"));
    }

    @Test
    void shouldFindVulnerabilitiesAffectingVersion() throws Exception {
        // Given
        Path path =
                Paths.get(
                        getClass()
                                .getResource(
                                        ServerSideVersionScanRule
                                                .PHP_KNOWN_VULNERABILITIES_RESOURCE)
                                .toURI());
        KnownVulnerabilities known = KnownVulnerabilities.load(path);
        // When
        List<String> cves =
                known.getVulnerabilities("7.3.10").stream().map(Vulnerability::cve).toList();
        // Then
        assertThat(cves, hasItem("CVE-2019-11043"));
        assertThat(cves, hasItem("CVE-2024-4577"));
    }

    @Test
    void shouldNotFindVulnerabilitiesForFixedOrUnaffectedVersions() throws Exception {
        // Given
        Path path =
                Files.writeString(
                        tempDir.resolve("vulnerabilities.json"),
                        """
                        { "vulnerabilities": [
                          { "cve": "CVE-2024-0001", "affected": [
                              { "introduced": "0", "fixed": "8.1.29", "assumed": true },
                              { "introduced": "8.2.0", "fixed": "8.2.20" },
                              { "introduced": "8.3.0", "fixed": "8.3.8" } ] }
                        ] }
                        """);
        KnownVulnerabilities known = KnownVulnerabilities.load(path);
        // When / Then
        assertThat(known.getVulnerabilities("8.1.29"), is(empty()));
        assertThat(known.getVulnerabilities("8.2.20"), is(empty()));
        assertThat(known.getVulnerabilities("8.3.8"), is(empty()));
        assertThat(known.getVulnerabilities("8.4.0"), is(empty()));
        assertThat(known.getVulnerabilities("8.1.28").size(), is(1));
        assertThat(known.getVulnerabilities("5.6.40").size(), is(1));
        assertThat(known.vulnerabilities().get(0).affected().get(0).assumed(), is(true));
    }

    @ParameterizedTest
    @CsvSource({
        "8.1.0, 8.1.5, 8.1.0, true",
        "8.1.0, 8.1.5, 8.1.4, true",
        "8.1.0, 8.1.5, 8.1.5, false",
        "8.1.0, 8.1.5, 8.0.30, false",
        "8.1.0, 8.1.5, 8.1, true",
        "8.1.0, 8.1.5, 8, false",
        "8.1.0, , 8.1.5, true",
        "8.1.0, , 9.0.0, true",
        "8.1.0, , 8.0.9, false",
    })
    void shouldMatchVersionRanges(
            String introduced, String fixed, String version, boolean expected) {
        // Given
        VersionRange range = new VersionRange(introduced, fixed, false);
        // When / Then
        assertThat(range.contains(version), is(expected));
    }

    @Test
    void shouldIgnoreVulnerabilitiesWithInvalidVersionRanges() throws Exception {
        // Given
        Path path =
                Files.writeString(
                        tempDir.resolve("bad-ranges.json"),
                        """
                        { "vulnerabilities": [
                          { "cve": "CVE-2024-0001", "affected": [ { "introduced": "7.3.x", "fixed": "7.3.11" } ] },
                          { "cve": "CVE-2024-0002", "affected": [ { "introduced": "8.1.0", "fixed": "8.1." } ] },
                          { "cve": "CVE-2024-0003", "affected": [ { "introduced": "99999999999999999999", "fixed": null } ] },
                          { "affected": [ { "introduced": "1.0", "fixed": null } ] },
                          { "cve": "CVE-2024-0005", "affected": [ { "introduced": "8.1.0", "fixed": "8.1.5" } ] }
                        ] }
                        """);
        // When
        KnownVulnerabilities known = KnownVulnerabilities.load(path);
        // Then
        assertThat(
                known.vulnerabilities().stream().map(Vulnerability::cve).toList(),
                contains("CVE-2024-0005"));
        assertThat(known.getVulnerabilities("8.1.2").size(), is(1));
    }

    @ParameterizedTest
    @CsvSource({
        "critical, CRITICAL",
        "High, HIGH",
        " medium , MEDIUM",
        "low, LOW",
        "moderate, LOW",
        ", LOW"
    })
    void shouldMapSeverities(String value, Severity expected) {
        assertThat(Severity.of(value), is(expected));
    }

    @Test
    void shouldTreatMissingSeverityAsLow() throws Exception {
        // Given
        Path path =
                Files.writeString(
                        tempDir.resolve("nosev.json"),
                        """
                        { "vulnerabilities": [
                          { "cve": "CVE-2024-0001", "affected": [ { "introduced": "1.0", "fixed": null } ] }
                        ] }
                        """);
        // When
        List<Vulnerability> vulnerabilities =
                KnownVulnerabilities.load(path).getVulnerabilities("1.5");
        // Then
        assertThat(vulnerabilities.size(), is(1));
        assertThat(vulnerabilities.get(0).getRisk(), is(Alert.RISK_LOW));
        assertThat(vulnerabilities.get(0).getSeverity(), is(Severity.LOW));
    }

    @ParameterizedTest
    @CsvSource({
        "8.1.2, 8.1.2, 0",
        "8.1, 8.1.0, 0",
        "8, 8.0.0, 0",
        "8.1.2, 8.1.10, -1",
        "8.10, 8.9.9, 1",
        "7.4.33, 8.0.0, -1",
        "10.0, 9.9.9, 1",
    })
    void shouldCompareVersionsNumerically(String a, String b, int expected) {
        // Given / When
        int result = KnownVulnerabilities.compareVersions(a, b);
        // Then
        if (expected == 0) {
            assertThat(result, is(0));
        } else if (expected < 0) {
            assertThat(result, is(lessThan(0)));
        } else {
            assertThat(result, is(greaterThan(0)));
        }
    }

    @Test
    void shouldReturnVulnerabilitiesMostSevereFirstThenByCve() throws Exception {
        // Given
        Path path =
                Files.writeString(
                        tempDir.resolve("order.json"),
                        """
                        { "vulnerabilities": [
                          { "cve": "CVE-2024-0002", "severity": "medium", "affected": [ { "introduced": "1.0", "fixed": "2.0" } ] },
                          { "cve": "CVE-2024-0001", "severity": "medium", "affected": [ { "introduced": "1.0", "fixed": null } ] },
                          { "cve": "CVE-2024-0005", "severity": "low", "affected": [ { "introduced": "1.0", "fixed": null } ] },
                          { "cve": "CVE-2024-0004", "severity": "critical", "affected": [ { "introduced": "1.0", "fixed": null } ] },
                          { "cve": "CVE-2024-0006", "severity": "high", "affected": [ { "introduced": "1.0", "fixed": null } ] },
                          { "cve": "CVE-2024-0003", "severity": "critical", "affected": [ { "introduced": "3.0", "fixed": null } ] }
                        ] }
                        """);
        // When
        List<String> cves =
                KnownVulnerabilities.load(path).getVulnerabilities("1.5").stream()
                        .map(Vulnerability::cve)
                        .toList();
        // Then
        assertThat(
                cves,
                contains(
                        "CVE-2024-0004",
                        "CVE-2024-0006",
                        "CVE-2024-0001",
                        "CVE-2024-0002",
                        "CVE-2024-0005"));
    }

    @ParameterizedTest
    @CsvSource({"8.1.2, true", "8.1.0, true", "8.1, false", "8, false", "8.1.2.3, true"})
    void shouldTellCompleteVersions(String version, boolean expected) {
        assertThat(KnownVulnerabilities.isCompleteVersion(version), is(expected));
    }

    @ParameterizedTest
    @CsvSource({"8.1, 8.2", "8, 9", "2.4, 2.5", "2.9, 2.10"})
    void shouldGetNextVersionAfterIncompleteVersion(String version, String expected) {
        assertThat(KnownVulnerabilities.nextVersionAfter(version), is(expected));
    }

    @ParameterizedTest
    @CsvSource({
        "8.1.0, 8.1.5, 8.1, true",
        "8.1.3, 8.1.5, 8.1, true",
        "8.0.0, 8.1.1, 8.1, true",
        "8.0.0, 8.1.0, 8.1, false",
        "8.2.0, 8.2.9, 8.1, false",
        "8.2.0, 8.2.9, 8, true",
        "8.2.0, , 8.1, false",
        "8.0.0, , 8.1, true",
        "0, 8.0.30, 8.1, false",
        "0, 8.0.30, 8, true",
    })
    void shouldMatchIncompleteVersionAgainstAnyReleaseInRange(
            String introduced, String fixed, String version, boolean expected) {
        // Given
        Vulnerability vulnerability =
                new Vulnerability(
                        "CVE-2024-0001",
                        null,
                        null,
                        null,
                        "low",
                        null,
                        null,
                        List.of(new VersionRange(introduced, fixed, false)),
                        null,
                        null,
                        null);
        // When / Then
        assertThat(vulnerability.affects(version), is(expected));
    }

    @Test
    void shouldPreferConfirmedRangeForIncompleteVersion() {
        // Given
        Vulnerability vulnerability =
                new Vulnerability(
                        "CVE-2024-0002",
                        null,
                        null,
                        null,
                        "critical",
                        null,
                        null,
                        List.of(
                                new VersionRange("0", "8.1.3", true),
                                new VersionRange("8.2.0", "8.2.9", false)),
                        null,
                        null,
                        null);
        // When / Then
        assertThat(vulnerability.matchingRange("8").orElseThrow().assumed(), is(false));
        assertThat(vulnerability.matchingRange("8.1").orElseThrow().assumed(), is(true));
        assertThat(vulnerability.matchingRange("8.3").isPresent(), is(false));
    }

    @Test
    void shouldDropVulnerabilityWithEmptyRangeOnLoad() throws Exception {
        // Given
        Path file =
                Files.writeString(
                        tempDir.resolve("empty-range.json"),
                        """
                        { "vulnerabilities": [
                          { "cve": "CVE-2001-1342", "severity": "low",
                            "affected": [ { "introduced": "1.3.20", "fixed": "1.3.20" } ] },
                          { "cve": "CVE-2001-0001", "severity": "low",
                            "affected": [ { "introduced": "1.3.19", "fixed": "1.3.20" } ] }
                        ] }
                        """);
        // When
        KnownVulnerabilities known = KnownVulnerabilities.load(file);
        // Then
        assertThat(
                known.vulnerabilities().stream().map(Vulnerability::cve).toList(),
                contains("CVE-2001-0001"));
    }
}
