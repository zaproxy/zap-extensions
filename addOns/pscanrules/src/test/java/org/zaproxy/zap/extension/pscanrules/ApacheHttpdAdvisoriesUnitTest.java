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
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.zaproxy.zap.extension.pscanrules.KnownVulnerabilities.VersionRange;
import org.zaproxy.zap.extension.pscanrules.KnownVulnerabilities.Vulnerability;

class ApacheHttpdAdvisoriesUnitTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void shouldListRecordUrlsFromDirectoryListing() {
        // Given
        String listing =
                """
                <a href="?C=N;O=D">Name</a> <a href="/security/">Parent</a>
                <a href="CVE-2024-47252.json">CVE-2024-47252.json</a>
                <a href="CVE-1999-1199.json">CVE-1999-1199.json</a>
                <a href="CVE-2024-47252.json">again</a> <a href="notes.json">x</a>
                """;
        // When
        var urls = ApacheHttpdAdvisories.recordUrls(listing);
        // Then
        assertThat(
                urls,
                contains(
                        "https://httpd.apache.org/security/json/CVE-1999-1199.json",
                        "https://httpd.apache.org/security/json/CVE-2024-47252.json"));
    }

    @Test
    void shouldConvertCve5RecordWithBranchUpperBound() throws Exception {
        // Given
        JsonNode record =
                json(
                        """
                        { "dataType": "CVE_RECORD", "dataVersion": "5.1",
                          "cveMetadata": { "cveId": "CVE-2024-47252", "state": "PUBLISHED" },
                          "containers": { "cna": {
                            "title": "Apache HTTP Server: mod_ssl error log variable escaping",
                            "affected": [ { "product": "Apache HTTP Server", "defaultStatus": "unaffected",
                              "versions": [ { "version": "2.4", "lessThanOrEqual": "2.4.63", "status": "affected", "versionType": "semver" },
                                            { "version": "2.6", "lessThan": "2.6.1", "status": "unaffected", "versionType": "semver" } ] } ],
                            "descriptions": [ { "lang": "en", "value": "Insufficient escaping of user-supplied data in mod_ssl in Apache HTTP Server 2.4.63 and earlier allows log injection.\\n\\nIn a logging configuration where CustomLog is used the data is not escaped." } ],
                            "metrics": [ { "other": { "type": "Textual description of severity", "content": { "text": "low" } } } ],
                            "timeline": [ { "lang": "en", "time": "2024-09-18T15:26:00.000Z", "value": "reported" },
                                          { "lang": "eng", "time": "2025-07-10", "value": "2.4.64 released" } ],
                            "references": [ { "url": "https://httpd.apache.org/security/vulnerabilities_24.html" } ] } } }
                        """);
        // When
        Vulnerability v = ApacheHttpdAdvisories.toVulnerability(record).orElseThrow();
        // Then
        assertThat(v.cve(), is("CVE-2024-47252"));
        assertThat(v.ghsa(), is(nullValue()));
        assertThat(v.name(), is("Apache HTTP Server: mod_ssl error log variable escaping"));
        assertThat(
                v.description(),
                is(
                        "Insufficient escaping of user-supplied data in mod_ssl in Apache HTTP Server 2.4.63 and earlier allows log injection."));
        assertThat(v.severity(), is("low"));
        assertThat(v.cvss(), is(nullValue()));
        assertThat(v.component(), is(nullValue()));
        assertThat(v.affected(), contains(new VersionRange("2.4.0", "2.4.64", false)));
        assertThat(v.published(), is("2025-07-10"));
        assertThat(v.source(), is(ApacheHttpdAdvisories.SOURCE_GENERATED));
        assertThat(
                v.links(),
                contains(
                        "https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2024-47252",
                        "https://nvd.nist.gov/vuln/detail/CVE-2024-47252",
                        "https://httpd.apache.org/security/json/CVE-2024-47252.json"));
    }

    @Test
    void shouldConvertCve5RecordWithExactVersionAndPublishedDate() throws Exception {
        // Given
        JsonNode record =
                cve5(
                        "CVE-2024-39884",
                        "\"datePublished\": \"2024-07-01T13:00:00.000Z\",",
                        "{ \"version\": \"2.4.60\", \"status\": \"affected\" }",
                        "important",
                        "{ \"time\": \"2024-07-03\", \"value\": \"2.4.61 released\" }");
        // When
        Vulnerability v = ApacheHttpdAdvisories.toVulnerability(record).orElseThrow();
        // Then
        assertThat(v.severity(), is("high"));
        assertThat(v.published(), is("2024-07-01"));
        assertThat(v.affected(), contains(new VersionRange("2.4.60", "2.4.61", false)));
    }

    @Test
    void shouldConvertCve5RecordWithOpenLowerBound() throws Exception {
        // Given
        JsonNode record =
                cve5(
                        "CVE-2022-37436",
                        "",
                        "{ \"version\": \"0\", \"lessThan\": \"2.4.55\", \"status\": \"affected\", \"versionType\": \"semver\" }",
                        "moderate",
                        "{ \"time\": \"2023-01-17\", \"value\": \"2.4.55 released\" }");
        // When
        Vulnerability v = ApacheHttpdAdvisories.toVulnerability(record).orElseThrow();
        // Then
        assertThat(v.severity(), is("medium"));
        assertThat(v.affected(), contains(new VersionRange("0", "2.4.55", false)));
    }

    @Test
    void shouldBumpPatchWhenCve5RecordHasNoRelease() throws Exception {
        // Given
        JsonNode record =
                cve5(
                        "CVE-2022-28614",
                        "",
                        "{ \"version\": \"2.4\", \"lessThanOrEqual\": \"2.4.53\", \"status\": \"affected\" }",
                        "low",
                        "{ \"time\": \"2022-06-08\", \"value\": \"public\" }");
        // When
        Vulnerability v = ApacheHttpdAdvisories.toVulnerability(record).orElseThrow();
        // Then
        assertThat(v.affected(), contains(new VersionRange("2.4.0", "2.4.54", false)));
        assertThat(v.published(), is("2022-06-08"));
    }

    @Test
    void shouldSkipRejectedCve5Record() throws Exception {
        // Given
        JsonNode record =
                json(
                        """
                        { "cveMetadata": { "cveId": "CVE-2024-0001", "state": "REJECTED" }, "containers": { "cna": {} } }
                        """);
        // When
        Optional<Vulnerability> v = ApacheHttpdAdvisories.toVulnerability(record);
        // Then
        assertThat(v.isPresent(), is(false));
    }

    @Test
    void shouldSkipRecordWithNotApplicableSeverity() {
        // Given, e.g. CVE-2016-5387, the "httpoxy" mitigation for CGI applications
        JsonNode record = cve4("CVE-2016-5387", "", "2.4:=:2.4.1,2.4.23", "", "n/a", "");
        // When
        Optional<Vulnerability> v = ApacheHttpdAdvisories.toVulnerability(record);
        // Then
        assertThat(v.isPresent(), is(false));
    }

    @Test
    void shouldFailOnUnknownSeverity() {
        // Given
        JsonNode record =
                cve5(
                        "CVE-2024-0001",
                        "",
                        "{ \"version\": \"2.4.60\", \"status\": \"affected\" }",
                        "severe",
                        "");
        // When / Then
        IllegalArgumentException e =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> ApacheHttpdAdvisories.toVulnerability(record));
        assertThat(e.getMessage(), containsString("severe"));
    }

    @Test
    void shouldFailOnOverlappingRanges() {
        // Given
        JsonNode record =
                cve5(
                        "CVE-2024-0001",
                        "",
                        "{ \"version\": \"0\", \"lessThan\": \"2.4.55\", \"status\": \"affected\" }, { \"version\": \"2.4\", \"lessThanOrEqual\": \"2.4.63\", \"status\": \"affected\" }",
                        "low",
                        "");
        // When / Then
        IllegalArgumentException e =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> ApacheHttpdAdvisories.toVulnerability(record));
        assertThat(e.getMessage(), containsString("overlapping"));
    }

    @Test
    void shouldFailOnRecordWithoutVersions() {
        // Given
        JsonNode record = cve5("CVE-2024-0001", "", "", "low", "");
        // When / Then
        IllegalArgumentException e =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> ApacheHttpdAdvisories.toVulnerability(record));
        assertThat(e.getMessage(), containsString("no affected versions"));
    }

    @Test
    void shouldConvertCve4RecordWithEnumeratedBranches() throws Exception {
        // Given
        JsonNode record =
                cve4(
                        "CVE-2017-7679",
                        "\"DATE_PUBLIC\": \"2017-06-19\",",
                        "2.2:=:2.2.32,2.2.31,2.2.0,2.2.3",
                        "2.4:=:2.4.25,2.4.23,2.4.1,2.4.7",
                        "important",
                        "{ \"time\": \"2017-06-19\", \"value\": \"2.4.26 released\" }, { \"time\": \"2017-07-11\", \"value\": \"2.2.34 released\" }");
        // When
        Vulnerability v = ApacheHttpdAdvisories.toVulnerability(record).orElseThrow();
        // Then
        assertThat(v.cve(), is("CVE-2017-7679"));
        assertThat(v.name(), is("Title of CVE-2017-7679"));
        assertThat(v.description(), is("Description of CVE-2017-7679, long enough to count."));
        assertThat(v.severity(), is("high"));
        assertThat(v.published(), is("2017-06-19"));
        assertThat(
                v.affected(),
                contains(
                        new VersionRange("2.2.0", "2.2.34", false),
                        new VersionRange("2.4.1", "2.4.26", false)));
        assertThat(
                v.links().get(0),
                is("https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2017-7679"));
    }

    @Test
    void shouldMakePossiblyAffectedVersionsBelowConfirmedOnesAnAssumedRange() throws Exception {
        // Given
        JsonNode record =
                cve4(
                        "CVE-2000-0505",
                        "",
                        "1.3:?=:1.3.0,1.3.11",
                        "1.3:=:1.3.12,1.3.13",
                        "moderate",
                        "{ \"time\": \"2000-10-13\", \"value\": \"1.3.14 released\" }");
        // When
        Vulnerability v = ApacheHttpdAdvisories.toVulnerability(record).orElseThrow();
        // Then
        assertThat(v.severity(), is("medium"));
        assertThat(v.published(), is("2000-10-13"));
        assertThat(
                v.affected(),
                contains(
                        new VersionRange("1.3.0", "1.3.12", true),
                        new VersionRange("1.3.12", "1.3.14", false)));
        assertThat(
                v.links().get(0),
                is("https://httpd.apache.org/security/vulnerabilities_13.html#CVE-2000-0505"));
    }

    @Test
    void shouldMakeOnlyPossiblyAffectedVersionsAnAssumedRange() throws Exception {
        // Given
        JsonNode record = cve4("CVE-2000-0001", "", "2.0:?=:2.0.35,2.0.36", "", "low", "");
        // When
        Vulnerability v = ApacheHttpdAdvisories.toVulnerability(record).orElseThrow();
        // Then
        assertThat(v.severity(), is("low"));
        assertThat(v.published(), is(""));
        assertThat(v.affected(), contains(new VersionRange("2.0.35", "2.0.37", true)));
    }

    @Test
    void shouldCapBranchWhichNeverGotARelease() throws Exception {
        // Given
        JsonNode record =
                cve4(
                        "CVE-2017-9798",
                        "",
                        "2.2:=:2.2.0,2.2.32",
                        "2.4:=:2.4.1,2.4.27",
                        "critical",
                        "{ \"time\": \"2017-09-18\", \"value\": \"public\" }, { \"time\": \"2017-10-01\", \"value\": \"2.4.28 released\" }, { \"time\": \"2017-10-01\", \"value\": \"2.2.35-never released\" }");
        // When
        Vulnerability v = ApacheHttpdAdvisories.toVulnerability(record).orElseThrow();
        // Then
        assertThat(v.severity(), is("critical"));
        assertThat(v.published(), is("2017-09-18"));
        assertThat(
                v.affected(),
                contains(
                        new VersionRange("2.2.0", "2.3.0", false),
                        new VersionRange("2.4.1", "2.4.28", false)));
    }

    @ParameterizedTest
    @CsvSource({
        "'2.4:!<:2.4.17', '2.4:<=:2.4.48', '2.4.49 released', 2.4.17, 2.4.49",
        "'2.4:>=:2.4.7', '2.4:<=:2.4.51', 'released in 2.4.53', 2.4.7, 2.4.53",
        "'2.4:<=:2.4.53', '', '', 2.4.0, 2.4.54",
        "'2.4:=:2.4.49', '', '2.4.50 release', 2.4.49, 2.4.50",
        "'2.3:=:2.3.4-alpha,2.3.5-alpha', '', '2.3.6 released', 2.3.4, 2.3.6",
    })
    void shouldConvertCve4Bounds(
            String versions1,
            String versions2,
            String timeline,
            String expectedIntroduced,
            String expectedFixed)
            throws Exception {
        // Given
        JsonNode record =
                cve4(
                        "CVE-2021-0001",
                        "",
                        versions1,
                        versions2,
                        "low",
                        timeline.isEmpty()
                                ? ""
                                : "{ \"time\": \"2021-01-01\", \"value\": \"" + timeline + "\" }");
        // When
        Vulnerability v = ApacheHttpdAdvisories.toVulnerability(record).orElseThrow();
        // Then
        assertThat(
                v.affected(), contains(new VersionRange(expectedIntroduced, expectedFixed, false)));
    }

    @Test
    void shouldIgnoreReleaseWhichIsNotNewerThanAffectedVersions() throws Exception {
        // Given, CVE-2001-1342 lists the fixing release as affected too
        JsonNode record =
                cve4(
                        "CVE-2001-1342",
                        "",
                        "1.3:?=:1.3.0,1.3.19",
                        "1.3:=:1.3.20",
                        "low",
                        "{ \"time\": \"2001-05-21\", \"value\": \"1.3.20 released\" }");
        // When
        Vulnerability v = ApacheHttpdAdvisories.toVulnerability(record).orElseThrow();
        // Then
        assertThat(
                v.affected(),
                contains(
                        new VersionRange("1.3.0", "1.3.20", true),
                        new VersionRange("1.3.20", "1.3.21", false)));
    }

    @Test
    void shouldUseZeroAsLowerBoundOfCve5BranchUpperBound() throws Exception {
        // Given
        JsonNode record =
                cve5(
                        "CVE-2026-0001",
                        "",
                        "{ \"version\": \"0\", \"lessThanOrEqual\": \"2.4.68\", \"status\": \"affected\" }",
                        "low",
                        "{ \"time\": \"2026-01-01\", \"value\": \"2.4.69 released\" }");
        // When
        Vulnerability v = ApacheHttpdAdvisories.toVulnerability(record).orElseThrow();
        // Then
        assertThat(v.affected(), contains(new VersionRange("0", "2.4.69", false)));
    }

    @Test
    void shouldFailOnTwoUpperBoundsForOneBranch() {
        // Given
        JsonNode record =
                cve5(
                        "CVE-2026-0001",
                        "",
                        "{ \"version\": \"2.4\", \"lessThanOrEqual\": \"2.4.60\", \"status\": \"affected\" }, "
                                + "{ \"version\": \"2.4\", \"lessThanOrEqual\": \"2.4.68\", \"status\": \"affected\" }",
                        "low",
                        "");
        // When / Then
        IllegalArgumentException e =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> ApacheHttpdAdvisories.toVulnerability(record));
        assertThat(e.getMessage(), containsString("two upper bounds"));
    }

    @Test
    void shouldFailOnUnknownVersionOperator() {
        // Given
        JsonNode record = cve4("CVE-2021-0001", "", "2.4:>:2.4.17", "", "low", "");
        // When / Then
        IllegalArgumentException e =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> ApacheHttpdAdvisories.toVulnerability(record));
        assertThat(e.getMessage(), containsString("'>'"));
    }

    @Test
    void shouldFailOnNonVersionValue() {
        // Given
        JsonNode record = cve4("CVE-2021-0001", "", "2.4:=:trunk", "", "low", "");
        // When / Then
        IllegalArgumentException e =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> ApacheHttpdAdvisories.toVulnerability(record));
        assertThat(e.getMessage(), containsString("trunk"));
    }

    @ParameterizedTest
    @CsvSource({"2.4.63, 2.4", "2.4, 2.4", "1.3.42, 1.3", "2, 2.0"})
    void shouldGetBranchOfVersion(String version, String expected) {
        assertThat(ApacheHttpdAdvisories.branchOf(version), is(expected));
    }

    private static JsonNode json(String json) {
        try {
            return MAPPER.readTree(json);
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    private static JsonNode cve5(
            String cve, String metaExtra, String versions, String severity, String timeline) {
        return json(
                "{ \"cveMetadata\": { \"cveId\": \""
                        + cve
                        + "\", \"state\": \"PUBLISHED\", "
                        + metaExtra
                        + " \"serial\": 1 },"
                        + " \"containers\": { \"cna\": { \"title\": \"Title\","
                        + " \"affected\": [ { \"product\": \"Apache HTTP Server\", \"versions\": ["
                        + versions
                        + "] } ],"
                        + " \"descriptions\": [ { \"lang\": \"en\", \"value\": \"A description which is long enough to be used.\" } ],"
                        + " \"metrics\": [ { \"other\": { \"content\": { \"text\": \""
                        + severity
                        + "\" } } } ],"
                        + " \"timeline\": ["
                        + timeline
                        + "] } } }");
    }

    /**
     * A CVE JSON 4 record; the versions are given as {@code branch:operator:v1,v2,...}, the branch
     * being used for the version name.
     */
    private static JsonNode cve4(
            String cve,
            String metaExtra,
            String versions1,
            String versions2,
            String severity,
            String timeline) {
        StringBuilder versionData = new StringBuilder();
        for (String versions : new String[] {versions1, versions2}) {
            if (versions.isEmpty()) {
                continue;
            }
            String[] parts = versions.split(":");
            for (String value : parts[2].split(",")) {
                if (versionData.length() > 0) {
                    versionData.append(',');
                }
                versionData
                        .append("{ \"version_name\": \"Apache HTTP Server ")
                        .append(parts[0])
                        .append("\", \"version_affected\": \"")
                        .append(parts[1])
                        .append("\", \"version_value\": \"")
                        .append(value)
                        .append("\" }");
            }
        }
        return json(
                "{ \"data_type\": \"CVE\", \"data_version\": \"4.0\","
                        + " \"CVE_data_meta\": { \"ID\": \""
                        + cve
                        + "\", \"STATE\": \"PUBLIC\", \"TITLE\": \"Title of "
                        + cve
                        + "\", "
                        + metaExtra
                        + " \"ASSIGNER\": \"security@apache.org\" },"
                        + " \"affects\": { \"vendor\": { \"vendor_data\": [ { \"vendor_name\": \"Apache Software Foundation\","
                        + " \"product\": { \"product_data\": [ { \"product_name\": \"Apache HTTP Server\", \"version\": { \"version_data\": ["
                        + versionData
                        + "] } } ] } } ] } },"
                        + " \"description\": { \"description_data\": [ { \"lang\": \"eng\", \"value\": \"Description of "
                        + cve
                        + ", long enough to count.\" } ] },"
                        + " \"impact\": [ { \"other\": \""
                        + severity
                        + "\" } ],"
                        + " \"timeline\": ["
                        + timeline
                        + "] }");
    }
}
