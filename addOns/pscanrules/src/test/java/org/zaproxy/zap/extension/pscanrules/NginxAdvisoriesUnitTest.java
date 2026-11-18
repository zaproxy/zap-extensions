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
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.zaproxy.zap.extension.pscanrules.KnownVulnerabilities.VersionRange;
import org.zaproxy.zap.extension.pscanrules.KnownVulnerabilities.Vulnerability;
import org.zaproxy.zap.extension.pscanrules.NginxAdvisories.Advisory;

class NginxAdvisoriesUnitTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String PAGE =
            """
            <html><body><ul>
            <li><p>Use-after-free in HTTP/2<br>Severity: medium<br><a href="https://my.f5.com/manage/s/article/K1">Advisory</a><br><a href="https://www.cve.org/CVERecord?id=CVE-2026-123633">CVE-2026-123633</a><br>Not vulnerable: 1.31.9+, 1.30.7+<br>Vulnerable: 1.19.7-1.31.8</p></li>

            <li><p>Memory corruption in HTTP &amp; mail<br>Severity: <b>major</b><br><a href="https://my.f5.com/manage/s/article/K2">Advisory</a><br><a href="https://www.cve.org/CVERecord?id=CVE-CVE-2026-121810">CVE-CVE-2026-121810</a><br>Not vulnerable: 1.31.9+<br>Vulnerable: 1.31.4-1.31.8</p></li>

            <li><p>Vulnerabilities with Windows 8.3 filename pseudonyms<br>Severity: <b>major</b><br><a href="http://www.coresecurity.com/content/filename-pseudonyms-vulnerabilities">CORE-2010-0121</a><br>Not vulnerable: 0.8.33+, 0.7.65+<br>Vulnerable: nginx/Windows 0.7.52-0.8.32</p></li>

            <li><p>An error log data are not sanitized<br>Severity: none<br><a href="https://www.cve.org/CVERecord?id=CVE-2009-4487">CVE-2009-4487</a><br>Not vulnerable: none<br>Vulnerable: all</p></li>
            </ul></body></html>
            """;

    @Test
    void shouldParseAdvisoriesPage() {
        // Given / When
        List<Advisory> advisories = NginxAdvisories.parse(PAGE);
        // Then
        assertThat(advisories.size(), is(4));
        assertThat(
                advisories.get(0),
                is(
                        new Advisory(
                                "CVE-2026-123633",
                                "Use-after-free in HTTP/2",
                                "medium",
                                "https://my.f5.com/manage/s/article/K1",
                                "1.19.7-1.31.8",
                                "1.31.9+, 1.30.7+")));
    }

    @Test
    void shouldParseBoldSeverityDoubledCvePrefixAndEntities() {
        // Given / When
        Advisory advisory = NginxAdvisories.parse(PAGE).get(1);
        // Then
        assertThat(advisory.id(), is("CVE-2026-121810"));
        assertThat(advisory.title(), is("Memory corruption in HTTP & mail"));
        assertThat(advisory.severity(), is("major"));
    }

    @Test
    void shouldParseAdvisoryWithoutCveUsingItsOwnLink() {
        // Given / When
        Advisory advisory = NginxAdvisories.parse(PAGE).get(2);
        // Then
        assertThat(advisory.id(), is("CORE-2010-0121"));
        assertThat(advisory.hasCve(), is(false));
        assertThat(
                advisory.advisoryUrl(),
                is("http://www.coresecurity.com/content/filename-pseudonyms-vulnerabilities"));
    }

    @Test
    void shouldFailToParsePageWithEntriesWhichAreNotMatched() {
        // Given
        String page =
                "<li><p>Title<br>Severity: low<br><a href=\"https://www.cve.org/CVERecord?id=CVE-2020-0001\">CVE-2020-0001</a><br>Not vulnerable: 1.0.6+<br>Vulnerable: 1.0.0-1.0.5</p></li>"
                        + "<li class=\"new\"><p>Title<br>Severity: low<br><a href=\"https://www.cve.org/CVERecord?id=CVE-2020-0002\">CVE-2020-0002</a><br>Not vulnerable: 1.0.6+<br>Vulnerable: 1.0.0-1.0.5</p></li>";
        // When / Then
        assertThrows(IllegalArgumentException.class, () -> NginxAdvisories.parse(page));
    }

    @Test
    void shouldParsePageWithOtherFormsOfLineBreak() {
        // Given
        String page =
                "<li><p>Title<BR/>Severity: low<br />"
                        + "<a href=\"https://www.cve.org/CVERecord?id=CVE-2020-0001\">CVE-2020-0001</a><Br>"
                        + "Not vulnerable: 1.0.6+<br/>Vulnerable: 1.0.0-1.0.5</p></li>";
        // When
        List<Advisory> advisories = NginxAdvisories.parse(page);
        // Then
        assertThat(advisories.size(), is(1));
        assertThat(advisories.get(0).vulnerable(), is("1.0.0-1.0.5"));
    }

    @Test
    void shouldFailToParsePageWithoutEntries() {
        // Given / When / Then
        assertThrows(IllegalArgumentException.class, () -> NginxAdvisories.parse("<html/>"));
    }

    @Test
    void shouldFailToParseEntryWithoutVulnerableVersions() {
        // Given
        String page =
                "<li><p>Title<br>Severity: low<br><a href=\"https://www.cve.org/CVERecord?id=CVE-2020-0001\">CVE-2020-0001</a><br>Not vulnerable: 1.0.1+</p></li>";
        // When / Then
        assertThrows(IllegalArgumentException.class, () -> NginxAdvisories.parse(page));
    }

    @Test
    void shouldConvertAdvisoryWithPatchedStableLineRemovedFromRange() throws Exception {
        // Given
        Advisory advisory = NginxAdvisories.parse(PAGE).get(0);
        // When
        Vulnerability v = NginxAdvisories.toVulnerability(advisory, null).orElseThrow();
        // Then
        assertThat(
                v.affected(),
                contains(
                        new VersionRange("1.19.7", "1.30.7", false),
                        new VersionRange("1.31.0", "1.31.9", false)));
        assertThat(v.severity(), is("medium"));
        assertThat(v.cve(), is("CVE-2026-123633"));
        assertThat(v.source(), is("nginx-advisories"));
        assertThat(
                v.links(),
                contains(
                        "https://my.f5.com/manage/s/article/K1",
                        "https://nginx.org/en/security_advisories.html",
                        "https://www.cve.org/CVERecord?id=CVE-2026-123633",
                        "https://nvd.nist.gov/vuln/detail/CVE-2026-123633"));
    }

    @Test
    void shouldNotAffectVersionsOfPatchedStableLine() throws Exception {
        // Given
        Advisory advisory =
                new Advisory(
                        "CVE-2022-41741",
                        "Memory corruption",
                        "medium",
                        null,
                        "1.1.3-1.23.1, 1.0.7-1.0.15",
                        "1.23.2+, 1.22.1+");
        // When
        Vulnerability v = NginxAdvisories.toVulnerability(advisory, null).orElseThrow();
        // Then
        assertThat(
                v.affected(),
                contains(
                        new VersionRange("1.0.7", "1.0.16", false),
                        new VersionRange("1.1.3", "1.22.1", false),
                        new VersionRange("1.23.0", "1.23.2", false)));
        assertThat(v.affects("1.22.0"), is(true));
        assertThat(v.affects("1.22.1"), is(false));
        assertThat(v.affects("1.22.9"), is(false));
        assertThat(v.affects("1.23.1"), is(true));
        assertThat(v.affects("1.23.2"), is(false));
    }

    @Test
    void shouldConvertSingleVulnerableVersion() {
        // Given
        Advisory advisory =
                new Advisory(
                        "CVE-2024-24989",
                        "NULL pointer dereference",
                        "major",
                        null,
                        "1.25.3",
                        "1.25.4+");
        // When
        Vulnerability v = NginxAdvisories.toVulnerability(advisory, null).orElseThrow();
        // Then
        assertThat(v.affected(), contains(new VersionRange("1.25.3", "1.25.4", false)));
        assertThat(v.severity(), is("high"));
    }

    @Test
    void shouldAssumeWindowsOnlyRanges() {
        // Given
        Advisory advisory = NginxAdvisories.parse(PAGE).get(2);
        // When
        Vulnerability v = NginxAdvisories.toVulnerability(advisory, null).orElseThrow();
        // Then
        assertThat(
                v.affected(),
                contains(
                        new VersionRange("0.7.52", "0.7.65", true),
                        new VersionRange("0.8.0", "0.8.33", true)));
        assertThat(
                v.links(),
                contains(
                        "http://www.coresecurity.com/content/filename-pseudonyms-vulnerabilities",
                        "https://nginx.org/en/security_advisories.html"));
        assertThat(v.published(), is(nullValue()));
        assertThat(v.description(), is(""));
    }

    @Test
    void shouldSkipAdvisoryRatedNone() {
        // Given
        Advisory advisory = NginxAdvisories.parse(PAGE).get(3);
        // When
        var vulnerability = NginxAdvisories.toVulnerability(advisory, null);
        // Then
        assertThat(vulnerability.isEmpty(), is(true));
    }

    @ParameterizedTest
    @CsvSource({"minor, low", "low, low", "medium, medium", "major, high"})
    void shouldMapSeverity(String nginx, String expected) {
        // Given
        Advisory advisory =
                new Advisory("CVE-2020-0001", "Title", nginx, null, "1.0.0-1.0.5", "1.0.6+");
        // When
        Vulnerability v = NginxAdvisories.toVulnerability(advisory, null).orElseThrow();
        // Then
        assertThat(v.severity(), is(expected));
    }

    @Test
    void shouldFailOnUnknownSeverity() {
        // Given
        Advisory advisory =
                new Advisory("CVE-2020-0001", "Title", "bad", null, "1.0.0-1.0.5", "1.0.6+");
        // When / Then
        assertThrows(
                IllegalArgumentException.class,
                () -> NginxAdvisories.toVulnerability(advisory, null));
    }

    @ParameterizedTest
    @CsvSource({"all", "1.0-1.2", "1.0.0-1.0.5-1.0.6", "1.0.0 - 1.0.5"})
    void shouldFailOnUnexpectedVulnerableVersions(String vulnerable) {
        // Given
        Advisory advisory =
                new Advisory("CVE-2020-0001", "Title", "low", null, vulnerable, "1.0.6+");
        // When / Then
        assertThrows(
                IllegalArgumentException.class,
                () -> NginxAdvisories.toVulnerability(advisory, null));
    }

    @Test
    void shouldAddDescriptionCvssAndPublishedDateFromCveRecord() throws Exception {
        // Given
        Advisory advisory =
                new Advisory(
                        "CVE-2024-7347",
                        "Buffer over-read",
                        "low",
                        null,
                        "1.5.13-1.27.0",
                        "1.27.1+, 1.26.2+");
        JsonNode record =
                json(
                        """
                        { "cveMetadata": { "cveId": "CVE-2024-7347", "datePublished": "2024-08-14T14:32:33.913Z" },
                          "containers": { "cna": {
                            "datePublic": "2024-08-14T14:00:00.000Z",
                            "descriptions": [ { "lang": "en", "value": "NGINX Open Source and NGINX Plus have a vulnerability in the ngx_http_mp4_module, which might allow an attacker to over-read worker process memory." } ],
                            "metrics": [ { "format": "CVSS", "cvssV3_1": { "baseScore": 5.7 }, "cvssV4_0": { "baseScore": 5.9 } } ] } } }
                        """);
        // When
        Vulnerability v = NginxAdvisories.toVulnerability(advisory, record).orElseThrow();
        // Then
        assertThat(
                v.description(),
                is(
                        "NGINX Open Source and NGINX Plus have a vulnerability in the ngx_http_mp4_module, which might allow an attacker to over-read worker process memory."));
        assertThat(v.cvss(), is(5.9));
        assertThat(v.published(), is("2024-08-14"));
    }

    @Test
    void shouldUseCvssV3WhenNoV4AndPublicDateWhenNoPublishedDate() throws Exception {
        // Given
        Advisory advisory =
                new Advisory("CVE-2010-2266", "Title", "low", null, "1.0.0-1.0.5", "1.0.6+");
        JsonNode record =
                json(
                        """
                        { "containers": { "cna": {
                            "datePublic": "2010-06-01T00:00:00.000Z",
                            "descriptions": [ { "lang": "en", "value": "Something happens." } ],
                            "metrics": [ { "cvssV3_0": { "baseScore": 7.5 } } ] } } }
                        """);
        // When
        Vulnerability v = NginxAdvisories.toVulnerability(advisory, record).orElseThrow();
        // Then
        assertThat(v.cvss(), is(7.5));
        assertThat(v.published(), is("2010-06-01"));
    }

    @Test
    void shouldLeaveDetailsEmptyForRecordWithoutThem() throws Exception {
        // Given
        Advisory advisory =
                new Advisory("CVE-2010-2266", "Title", "low", null, "1.0.0-1.0.5", "1.0.6+");
        JsonNode record = json("{ \"containers\": { \"cna\": {} } }");
        // When
        Vulnerability v = NginxAdvisories.toVulnerability(advisory, record).orElseThrow();
        // Then
        assertThat(v.description(), is(""));
        assertThat(v.cvss(), is(nullValue()));
        assertThat(v.published(), is(nullValue()));
        assertThat(v.affected().isEmpty(), is(false));
    }

    private static JsonNode json(String json) throws Exception {
        return MAPPER.readTree(json);
    }
}
