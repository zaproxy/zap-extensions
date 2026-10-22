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
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.startsWith;
import static org.mockito.BDDMockito.given;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.extension.pscanrules.KnownVulnerabilities.Vulnerability;
import org.zaproxy.zap.extension.pscanrules.ServerSideVersionScanRule.DetectedVersion;
import org.zaproxy.zap.extension.pscanrules.ServerSideVersionScanRule.Technology;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

class ServerSideVersionScanRuleUnitTest extends PassiveScannerTest<ServerSideVersionScanRule> {

    private static final String PROBLEMS =
            """
            { "vulnerabilities": [
              { "cve": "CVE-2024-0001", "name": "Medium one", "severity": "medium",
                "links": [ "https://example.com/1" ],
                "affected": [ { "introduced": "8.1.0", "fixed": "8.1.5" } ] },
              { "cve": "CVE-2024-0002", "name": "Critical one", "severity": "critical",
                "links": [ "https://example.com/2" ],
                "affected": [ { "introduced": "0", "fixed": "8.1.3", "assumed": true },
                              { "introduced": "8.2.0", "fixed": "8.2.9" } ] },
              { "cve": "CVE-2024-0003", "name": "Low one", "severity": "low",
                "links": [ "https://example.com/3" ],
                "affected": [ { "introduced": "0", "fixed": "8.0.30", "assumed": true } ] }
            ] }
            """;

    @TempDir Path tempDir;

    @Override
    protected ServerSideVersionScanRule createScanner() {
        return new ServerSideVersionScanRule();
    }

    @BeforeEach
    void setUpVulnerabilities() throws Exception {
        ServerSideVersionScanRule.clear();
        given(passiveScanData.getTechSet()).willReturn(TechSet.getAllTech());
        ServerSideVersionScanRule.setKnownVulnerabilitiesFile(
                Technology.PHP,
                Files.writeString(tempDir.resolve("vulnerabilities.json"), PROBLEMS));
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(tags.size(), is(equalTo(12)));
        assertThat(tags.containsKey(CommonAlertTag.OWASP_2025_A03_SUPPLY_CHAIN.getTag()), is(true));
        assertThat(tags.containsKey(CommonAlertTag.OWASP_2021_A06_VULN_COMP.getTag()), is(true));
        assertThat(tags.containsKey(CommonAlertTag.OWASP_2017_A09_VULN_COMP.getTag()), is(true));
        assertThat(
                tags.containsKey(
                        CommonAlertTag.WSTG_V42_INFO_08_FINGERPRINT_APP_FRAMEWORK.getTag()),
                is(true));
        assertThat(tags.containsKey(PolicyTag.API.getTag()), is(true));
        assertThat(tags.containsKey(PolicyTag.PENTEST.getTag()), is(true));
        assertThat(tags.containsKey(PolicyTag.QA_CICD.getTag()), is(true));
        assertThat(tags.containsKey(PolicyTag.QA_FULL.getTag()), is(true));
        assertThat(tags.containsKey(PolicyTag.QA_STD.getTag()), is(true));
        assertThat(
                tags.get("CVE-2024-0001"),
                is(equalTo("https://nvd.nist.gov/vuln/detail/cve-2024-0001")));
        assertThat(tags.containsKey("CVE-2024-0002"), is(true));
        assertThat(tags.containsKey("CVE-2024-0003"), is(true));
    }

    @Test
    void shouldIncludeAllBundledCvesInAlertTags() {
        // Given
        ServerSideVersionScanRule.setKnownVulnerabilitiesFile(
                Technology.PHP,
                Path.of(
                        getClass()
                                .getResource(
                                        ServerSideVersionScanRule
                                                .PHP_KNOWN_VULNERABILITIES_RESOURCE)
                                .getPath()));
        // When
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(tags.containsKey("CVE-2024-4577"), is(true));
        assertThat(tags.containsKey("CVE-2019-11043"), is(true));
        assertThat(tags.size(), is(greaterThan(50)));
    }

    @ParameterizedTest
    @CsvSource({
        "X-Powered-By: PHP/8.2.12, X-Powered-By, 8.2.12, PHP/8.2.12",
        "X-Powered-By: PHP/7.4, X-Powered-By, 7.4, PHP/7.4",
        "X-Powered-By: PHP/8, X-Powered-By, 8, PHP/8",
        "X-Powered-By: php/5.6.40, X-Powered-By, 5.6.40, php/5.6.40",
        "X-Powered-By: PHP/7.4.3-4ubuntu2.19, X-Powered-By, 7.4.3, PHP/7.4.3",
        "X-Powered-By: PHP/5.4.45-0+deb7u14, X-Powered-By, 5.4.45, PHP/5.4.45",
        "Server: Apache/2.4.41 (Ubuntu) PHP/7.4.3, Server, 7.4.3, PHP/7.4.3",
        "Server: Apache/2.2.15 (CentOS) PHP/5.3.3 mod_ssl/2.2.15 OpenSSL/1.0.1e, Server, 5.3.3, PHP/5.3.3",
        "X-Powered-By: PHP/8.1.2 ZendServer/2021.0, X-Powered-By, 8.1.2, PHP/8.1.2",
        "X-Powered-By: PHP/8.0.30 PleskLin, X-Powered-By, 8.0.30, PHP/8.0.30",
        "'X-Powered-By: PHP/8.3.0, ASP.NET', X-Powered-By, 8.3.0, PHP/8.3.0",
    })
    void shouldExtractPhpVersionFromHeader(
            String header, String expectedName, String expectedVersion, String expectedEvidence)
            throws Exception {
        // Given
        HttpResponseHeader responseHeader = createResponseHeader(header);
        // When
        List<DetectedVersion> versions = ServerSideVersionScanRule.getVersions(responseHeader);
        // Then
        assertThat(
                versions,
                contains(
                        new DetectedVersion(
                                Technology.PHP, expectedName, expectedVersion, expectedEvidence)));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "Server: Apache/2.4.41 (Ubuntu)",
                "X-Powered-By: ASP.NET",
                "X-Powered-By: Express",
                "X-Powered-By: PHP",
                "X-Powered-By: PHP/",
                "X-Powered-By: PHP/dev",
                "Server: Apache/2.4 mod_php/7.4.3",
                "X-Powered-By: Some-PHP/1.0",
                "X-Powered-By: PHPUnit/9.5",
                "Set-Cookie: PHPSESSID=abc123; path=/",
                "X-Powered-By: Zend Framework/3.0 Smarty/4.3.0",
            })
    void shouldNotExtractPhpVersionWhenNoneDisclosed(String header) throws Exception {
        // Given
        HttpResponseHeader responseHeader = createResponseHeader(header);
        // When
        List<DetectedVersion> versions = ServerSideVersionScanRule.getVersions(responseHeader);
        // Then
        assertThat(versions, is(empty()));
    }

    @Test
    void shouldExtractPhpVersionsFromMultipleHeaders() throws Exception {
        // Given
        HttpResponseHeader responseHeader =
                createResponseHeader(
                        "Server: Apache/2.4.41 PHP/7.4.3\r\nX-Powered-By: PHP/7.4.3\r\nX-Powered-By: PHP/8.1.0");
        // When
        List<DetectedVersion> versions = ServerSideVersionScanRule.getVersions(responseHeader);
        // Then
        assertThat(
                versions.stream().map(v -> v.headerName() + " " + v.version()).toList(),
                contains("Server 7.4.3", "X-Powered-By 7.4.3", "X-Powered-By 8.1.0"));
    }

    @Test
    void shouldRaiseAlertWithRiskOfMostSevereVulnerabilityListingAllVulnerabilities()
            throws Exception {
        // Given
        HttpMessage msg = createMessage("http://www.example.com/", "X-Powered-By: PHP/8.1.2");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertThat(alert.getRisk(), is(Alert.RISK_HIGH));
        assertThat(alert.getConfidence(), is(Alert.CONFIDENCE_MEDIUM));
        assertThat(alert.getAlertRef(), is("20020-1"));
        assertThat(alert.getName(), is("PHP Version with Known Vulnerabilities"));
        assertThat(alert.getEvidence(), is("PHP/8.1.2"));
        assertThat(alert.getDescription(), not(containsString("PHP version 8.1.2")));
        assertThat(alert.getDescription(), not(containsString("X-Powered-By")));
        assertThat(alert.getTags().containsKey("CVE-2024-0002"), is(true));
        assertThat(alert.getTags().containsKey("CVE-2024-0001"), is(true));
        assertThat(alert.getTags().containsKey("CVE-2024-0003"), is(false));
        assertThat(alert.getTags().containsKey(PolicyTag.QA_FULL.getTag()), is(true));
        assertThat(alert.getDescription(), containsString("backport security fixes"));
        assertThat(alert.getDescription(), not(containsString("CVE-")));
        assertThat(alert.getDescription(), not(containsString("https://")));
        assertThat(
                alert.getReference(),
                is(
                        "https://www.php.net/supported-versions.php\nhttps://github.com/php/php-src/security/advisories\n"
                                + ServerSideVersionScanRule.PHP_HELP_URL
                                + "#cve-2024-0002\n"
                                + ServerSideVersionScanRule.PHP_HELP_URL
                                + "#cve-2024-0001"));
        assertThat(
                alert.getOtherInfo(),
                is(
                        "The server disclosed that it is running PHP version 8.1.2 via the \"X-Powered-By\" HTTP response header.\n\n"
                                + "2 known vulnerabilities: 1 critical, 0 high, 1 medium, 0 low.\n\n"
                                + "Critical: CVE-2024-0002\n\n"
                                + "Medium: CVE-2024-0001"));
        assertThat(alert.getOtherInfo(), not(containsString("Critical one")));
        assertThat(alert.getCweId(), is(1395));
    }

    @Test
    void shouldListCvesOfSameSeverityOnOneLine() throws Exception {
        // Given
        ServerSideVersionScanRule.setKnownVulnerabilitiesFile(
                Technology.PHP,
                Files.writeString(
                        tempDir.resolve("same-severity.json"),
                        """
                        { "vulnerabilities": [
                          { "cve": "CVE-2024-0010", "severity": "high", "published": "2024-01-01",
                            "affected": [ { "introduced": "8.1.0", "fixed": "8.1.5" } ] },
                          { "cve": "CVE-2024-0011", "severity": "high", "published": "2024-02-01",
                            "affected": [ { "introduced": "8.1.0", "fixed": "8.1.5" } ] },
                          { "cve": "CVE-2024-0012", "severity": "low",
                            "affected": [ { "introduced": "8.1.0", "fixed": "8.1.5" } ] }
                        ] }
                        """));
        HttpMessage msg = createMessage("http://www.example.com/", "X-Powered-By: PHP/8.1.2");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(
                alertsRaised.get(0).getOtherInfo(),
                is(
                        "The server disclosed that it is running PHP version 8.1.2 via the \"X-Powered-By\" HTTP response header.\n\n"
                                + "3 known vulnerabilities: 0 critical, 2 high, 0 medium, 1 low.\n\n"
                                + "High: CVE-2024-0010, CVE-2024-0011\n\n"
                                + "Low: CVE-2024-0012"));
    }

    @Test
    void shouldRaiseMediumRiskAlertWhenMostSevereVulnerabilityIsMedium() throws Exception {
        // Given
        HttpMessage msg = createMessage("http://www.example.com/", "X-Powered-By: PHP/8.1.4");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getRisk(), is(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(0).getOtherInfo(), endsWith("\n\nMedium: CVE-2024-0001"));
        assertThat(alertsRaised.get(0).getOtherInfo(), not(containsString("CVE-2024-0002")));
    }

    @Test
    void shouldRaiseLowConfidenceAlertWhenAllMatchesAreAssumed() throws Exception {
        // Given
        HttpMessage msg = createMessage("http://www.example.com/", "X-Powered-By: PHP/5.6.40");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertThat(alert.getRisk(), is(Alert.RISK_HIGH));
        assertThat(alert.getConfidence(), is(Alert.CONFIDENCE_LOW));
        assertThat(
                alert.getOtherInfo(),
                endsWith(
                        "assumed to be affected because older, end-of-life release branches rarely receive fixes.\n\n"
                                + "Critical: CVE-2024-0002\n\n"
                                + "Low: CVE-2024-0003"));
    }

    @Test
    void shouldRaiseLowConfidenceAlertWhenVersionIsIncomplete() throws Exception {
        // Given
        HttpMessage msg = createMessage("http://www.example.com/", "X-Powered-By: PHP/8.1");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getConfidence(), is(Alert.CONFIDENCE_LOW));
        assertThat(
                alertsRaised.get(0).getOtherInfo(),
                startsWith("The server disclosed that it is running PHP version 8.1 via"));
    }

    @Test
    void shouldNotFailOnHugeVersionNumbers() throws Exception {
        // Given
        HttpMessage msg =
                createMessage(
                        "http://www.example.com/",
                        "X-Powered-By: PHP/99999999999999999999.1.1 PHP/999999.999999.999999");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, is(empty()));
    }

    @Test
    void shouldNotRaiseAlertWhenVersionHasNoKnownVulnerabilities() throws Exception {
        // Given
        HttpMessage msg = createMessage("http://www.example.com/", "X-Powered-By: PHP/8.3.0");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, is(empty()));
    }

    @Test
    void shouldNotRaiseAlertWhenPhpTechIsNotEnabled() throws Exception {
        // Given
        TechSet techSet = new TechSet(TechSet.getAllTech());
        techSet.exclude(Tech.PHP);
        given(passiveScanData.getTechSet()).willReturn(techSet);
        HttpMessage msg = createMessage("http://www.example.com/", "X-Powered-By: PHP/8.1.2");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, is(empty()));
    }

    @Test
    void shouldRaiseAlertWhenTechSetIsNotAvailable() throws Exception {
        // Given
        given(passiveScanData.getTechSet()).willReturn(null);
        HttpMessage msg = createMessage("http://www.example.com/", "X-Powered-By: PHP/8.1.2");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    void shouldNotRaiseAlertWhenNoVersionDisclosed() throws Exception {
        // Given
        HttpMessage msg = createMessage("http://www.example.com/", "X-Powered-By: ASP.NET");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, is(empty()));
    }

    @Test
    void shouldRaiseOneAlertPerSiteTechnologyAndVersion() throws Exception {
        // Given
        HttpMessage msg1 = createMessage("http://www.example.com/a", "X-Powered-By: PHP/8.1.2");
        HttpMessage msg2 = createMessage("http://www.example.com/b", "X-Powered-By: PHP/8.1.2");
        HttpMessage msg3 = createMessage("https://www.example.com/a", "X-Powered-By: PHP/8.1.2");
        HttpMessage msg4 = createMessage("http://other.example.org/", "X-Powered-By: PHP/8.1.2");
        HttpMessage msg5 =
                createMessage("http://www.example.com/legacy", "X-Powered-By: PHP/5.6.40");
        // When
        scanHttpResponseReceive(msg1);
        scanHttpResponseReceive(msg2);
        scanHttpResponseReceive(msg3);
        scanHttpResponseReceive(msg4);
        scanHttpResponseReceive(msg5);
        // Then
        assertThat(alertsRaised, hasSize(4));
        assertThat(alertsRaised.get(3).getEvidence(), is("PHP/5.6.40"));
    }

    @Test
    void shouldAlertAgainAfterClear() throws Exception {
        // Given
        HttpMessage msg = createMessage("http://www.example.com/", "X-Powered-By: PHP/8.1.2");
        scanHttpResponseReceive(msg);
        // When
        ServerSideVersionScanRule.clear();
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(2));
    }

    @Test
    void shouldHaveNoKnownVulnerabilitiesWhenFileMissing() throws Exception {
        // Given
        ServerSideVersionScanRule.setKnownVulnerabilitiesFile(
                Technology.PHP, tempDir.resolve("missing.json"));
        HttpMessage msg = createMessage("http://www.example.com/", "X-Powered-By: PHP/5.3.3");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(
                ServerSideVersionScanRule.getKnownVulnerabilities(Technology.PHP, "5.3.3"),
                is(empty()));
        assertThat(alertsRaised, is(empty()));
    }

    @Test
    void shouldReturnVulnerabilitiesMostSevereFirst() {
        // Given / When
        List<Vulnerability> vulnerabilities =
                ServerSideVersionScanRule.getKnownVulnerabilities(Technology.PHP, "8.1.2");
        // Then
        assertThat(
                vulnerabilities.stream().map(Vulnerability::cve).toList(),
                contains("CVE-2024-0002", "CVE-2024-0001"));
    }

    @Test
    void shouldHaveGenericRuleName() {
        assertThat(rule.getName(), is("Server Side Technology Version with Known Vulnerabilities"));
    }

    @Test
    void shouldReturnExpectedExampleAlert() {
        // Given / When
        List<Alert> alerts = rule.getExampleAlerts();
        // Then
        assertThat(alerts, hasSize(1));
        Alert alert = alerts.get(0);
        assertThat(alert.getAlertRef(), is("20020-1"));
        assertThat(alert.getName(), is("PHP Version with Known Vulnerabilities"));
        assertThat(alert.getRisk(), is(Alert.RISK_HIGH));
        assertThat(alert.getConfidence(), is(Alert.CONFIDENCE_MEDIUM));
        assertThat(alert.getEvidence(), is("PHP/8.1.2"));
        assertThat(
                alert.getOtherInfo(),
                is(
                        "The server disclosed that it is running PHP version 8.1.2 via the \"X-Powered-By\" HTTP response header.\n\n"
                                + "1 known vulnerabilities: 0 critical, 1 high, 0 medium, 0 low.\n\nHigh: CVE-2024-4577"));
        assertThat(
                alert.getTags().entrySet().containsAll(rule.getAlertTags().entrySet()), is(true));
        assertThat(alert.getTags().containsKey("CVE-2024-0003"), is(true));
        assertThat(alert.getDescription(), not(containsString("https://")));
        assertThat(
                alert.getReference(),
                containsString("\n" + ServerSideVersionScanRule.PHP_HELP_URL + "#cve-2024-4577"));
        assertThat(alert.getCweId(), is(1395));
        assertThat(alert.getWascId(), is(13));
    }

    private static HttpMessage createMessage(String url, String header) throws Exception {
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET " + url + " HTTP/1.1");
        msg.setResponseHeader(createResponseHeader(header));
        return msg;
    }

    private static HttpResponseHeader createResponseHeader(String headers)
            throws HttpMalformedHeaderException {
        return new HttpResponseHeader(
                "HTTP/1.1 200 OK\r\n" + headers + "\r\nContent-Type: text/html\r\n\r\n");
    }
}
