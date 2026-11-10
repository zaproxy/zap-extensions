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
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.zaproxy.zap.extension.pscanrules.AdvisoryUtils.ParsedRange;
import org.zaproxy.zap.extension.pscanrules.KnownVulnerabilities.Vulnerability;

class PhpAdvisoriesUnitTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @ParameterizedTest
    @CsvSource({
        "'< 8.2.35', '8.2.35', 8.2.0, 8.2.35, true",
        "'<8.2.34', '8.2.34', 8.2.0, 8.2.34, true",
        "'<=8.0.27', '8.0.28', 8.0.0, 8.0.28, true",
        "'<=8.0.27', '', 8.0.0, 8.0.28, false",
        "'>=8.1.0, <=8.1.15', '8.1.16', 8.1.0, 8.1.16, true",
        "'> 8.1.11, < 8.1.28', ' 8.1.28', 8.1.12, 8.1.28, true",
        "'8.2.12', '8.2.13', 8.2.12, 8.2.13, true",
        "'8.3.6', '', 8.3.6, 8.3.7, false",
        "'< 8.1.29', '8.1.29, 8.2.20, 8.3.8.', 8.1.0, 8.1.29, true",
    })
    void shouldParseSingleRanges(
            String range, String patched, String introduced, String fixed, boolean fixedKnown) {
        // Given / When
        List<ParsedRange> ranges = PhpAdvisories.parseVersionRanges(range, patched);
        // Then
        assertThat(ranges, hasSize(1));
        assertThat(ranges.get(0).introduced(), is(introduced));
        assertThat(ranges.get(0).fixed(), is(fixed));
        assertThat(ranges.get(0).fixedKnown(), is(fixedKnown));
    }

    @Test
    void shouldParseHyphenatedListPreferringStatedPatchedVersions() {
        // Given / When
        List<ParsedRange> ranges =
                PhpAdvisories.parseVersionRanges(
                        "7.3.27 - 7.3.33, 7.4.15 - 7.4.33, 8.0.2 - 8.0.30, 8.1.0 - 8.1.28, 8.2.0 - 8.2.19, 8.3.0 - 8.3.7",
                        "8.1.29, 8.2.20, 8.3.8.");
        // Then
        assertThat(
                ranges,
                contains(
                        new ParsedRange("7.3.27", "7.3.34", false, false, false),
                        new ParsedRange("7.4.15", "7.4.34", false, false, false),
                        new ParsedRange("8.0.2", "8.0.31", false, false, false),
                        new ParsedRange("8.1.0", "8.1.29", false, true, false),
                        new ParsedRange("8.2.0", "8.2.20", false, true, false),
                        new ParsedRange("8.3.0", "8.3.8", false, true, false)));
    }

    @ParameterizedTest
    @CsvSource({"all versions", "~8.1", "'< 8.x'"})
    void shouldFailOnUnrecognisedRange(String range) {
        assertThrows(
                IllegalArgumentException.class,
                () -> PhpAdvisories.parseVersionRanges(range, null));
    }

    @Test
    void shouldExtendLowestOpenRangeDownToZero() {
        // Given
        List<ParsedRange> ranges =
                List.of("< 8.3.8", "< 8.1.29", "< 8.2.20").stream()
                        .flatMap(r -> PhpAdvisories.parseVersionRanges(r, null).stream())
                        .toList();
        // When
        List<ParsedRange> result = PhpAdvisories.consolidate(ranges, "GHSA-x");
        // Then
        assertThat(
                result,
                contains(
                        new ParsedRange("0", "8.1.29", true, false, true),
                        new ParsedRange("8.2.0", "8.2.20", false, false, true),
                        new ParsedRange("8.3.0", "8.3.8", false, false, true)));
    }

    @Test
    void shouldExtendLowestRangeStartingAtBranchStart() {
        // Given
        List<ParsedRange> ranges =
                Stream.concat(
                                PhpAdvisories.parseVersionRanges(">=8.1.0, <=8.1.15", "8.1.16")
                                        .stream(),
                                PhpAdvisories.parseVersionRanges(">=8.2.0, <=8.2.2", "8.2.3")
                                        .stream())
                        .toList();
        // When
        List<ParsedRange> result = PhpAdvisories.consolidate(ranges, "GHSA-x");
        // Then
        assertThat(result.get(0).introduced(), is("0"));
        assertThat(result.get(0).assumed(), is(true));
        assertThat(result.get(1).introduced(), is("8.2.0"));
        assertThat(result.get(1).assumed(), is(false));
    }

    @Test
    void shouldNotExtendLowestRangeWithStatedLowerBound() {
        // Given
        List<ParsedRange> ranges =
                PhpAdvisories.parseVersionRanges("7.4.15 - 7.4.33, 8.0.2 - 8.0.30", null);
        // When
        List<ParsedRange> result = PhpAdvisories.consolidate(ranges, "GHSA-x");
        // Then
        assertThat(result.get(0).introduced(), is("7.4.15"));
        assertThat(result.get(0).assumed(), is(false));
    }

    @Test
    void shouldFailOnOverlappingRanges() {
        // Given
        List<ParsedRange> ranges =
                List.of(
                        new ParsedRange("8.1.0", "8.1.29", false),
                        new ParsedRange("8.1.10", "8.1.30", false));
        // When / Then
        assertThrows(
                IllegalArgumentException.class, () -> PhpAdvisories.consolidate(ranges, "GHSA-x"));
    }

    @ParameterizedTest
    @CsvSource({"8.1.29, 8.1.30", "8.1, 8.1.1", "8, 8.0.1"})
    void shouldBumpPatch(String version, String expected) {
        assertThat(AdvisoryUtils.bumpPatch(version), is(expected));
    }

    @ParameterizedTest
    @CsvSource({"8.1.29, 8.1.0", "8, 8.0.0", "8.1, 8.1.0"})
    void shouldFindBranchStart(String version, String expected) {
        assertThat(AdvisoryUtils.branchStart(version), is(expected));
    }

    @ParameterizedTest
    @CsvSource({"8.1.0, true", "8.1, true", "8.1.1, false", "8, false"})
    void shouldRecogniseBranchStarts(String version, boolean expected) {
        assertThat(AdvisoryUtils.isBranchStart(version), is(expected));
    }

    @Test
    void shouldNormalisePatchedVersions() {
        assertThat(
                PhpAdvisories.normalizePatched("8.1.29, 8.2.20, 8.3.8."),
                contains("8.1.29", "8.2.20", "8.3.8"));
        assertThat(PhpAdvisories.normalizePatched(" 8.1.28"), contains("8.1.28"));
        assertThat(PhpAdvisories.normalizePatched(""), hasSize(0));
        assertThat(PhpAdvisories.normalizePatched(null), hasSize(0));
    }

    @Test
    void shouldTakeFirstParagraphAsPlainText() {
        String md =
                "### Summary\n\nA **bad** `thing` in [foo](https://x) happens.\nMore here.\n\n### Details\nlong";
        assertThat(AdvisoryUtils.firstParagraph(md), is("A bad thing in foo happens. More here."));
    }

    @Test
    void shouldSkipGreetingParagraphs() {
        String md = "Hi,\n\nThere is a problem with the thing that does the stuff.\n\nRegards";
        assertThat(
                AdvisoryUtils.firstParagraph(md),
                is("There is a problem with the thing that does the stuff."));
    }

    @Test
    void shouldPreferSummarySectionEvenWithoutBlankLineAfterHeading() {
        String md =
                "### Summary\r\nCertain inputs trigger an endless loop in the thing.\r\n\r\n### Details\r\nA pattern has not been identified yet at all.";
        assertThat(
                AdvisoryUtils.firstParagraph(md),
                is("Certain inputs trigger an endless loop in the thing."));
    }

    @Test
    void shouldPreferImpactSectionOverDisclosureEmailPreamble() {
        String md =
                "Hi,\r\n\r\nI am a researcher. We recently found a vulnerability on PHP and would like to report it.\r\n\r\n"
                        + "# Impact\r\n\r\nAn attacker can execute arbitrary PHP code on the remote server.\r\n\r\n# Details\r\n\r\nLots more.";
        assertThat(
                AdvisoryUtils.firstParagraph(md),
                is("An attacker can execute arbitrary PHP code on the remote server."));
    }

    @Test
    void shouldKeepUnderscoresInIdentifiers() {
        String md = "Certain inputs provided to mb_encode_mimeheader trigger an endless loop.";
        assertThat(AdvisoryUtils.firstParagraph(md), is(md));
    }

    @Test
    void shouldSkipCodeBlocks() {
        String md =
                "### PoC\n```\n<?php echo 'a very long line of code that is not a description at all';\n```\nRun the above and the process hangs forever.";
        assertThat(
                AdvisoryUtils.firstParagraph(md),
                is("Run the above and the process hangs forever."));
    }

    @Test
    void shouldFallBackToShortParagraphWhenNothingElse() {
        assertThat(AdvisoryUtils.firstParagraph("Short."), is("Short."));
        assertThat(AdvisoryUtils.firstParagraph(""), is(""));
    }

    @Test
    void shouldTruncateLongDescriptions() {
        String text = AdvisoryUtils.firstParagraph("word ".repeat(200));
        assertThat(text.length(), is(lessThanOrEqualTo(503)));
        assertThat(text, endsWith("..."));
    }

    @Test
    void shouldConvertAdvisory() throws Exception {
        // Given
        JsonNode advisory =
                MAPPER.readTree(
                        """
                        {
                          "ghsa_id": "GHSA-7875-c8px-7q5f", "cve_id": "CVE-2026-93682", "state": "published", "withdrawn_at": null,
                          "html_url": "https://github.com/php/php-src/security/advisories/GHSA-7875-c8px-7q5f",
                          "summary": "Out-of-bounds read in the HTTP stream wrapper",
                          "description": "### Summary\\n\\nAn OOB read in the wrapper when following a redirect.\\n\\n### Details\\nlots",
                          "severity": "medium", "published_at": "2026-09-24T10:07:25Z",
                          "cvss_severities": { "cvss_v3": { "score": 5.3 }, "cvss_v4": { "score": 6.0 } },
                          "vulnerabilities": [
                            { "package": { "ecosystem": "php", "name": "ext-standard" }, "vulnerable_version_range": "<8.2.34", "patched_versions": "8.2.34" },
                            { "package": { "ecosystem": "php", "name": "ext-standard" }, "vulnerable_version_range": "<8.3.35", "patched_versions": "8.3.35" }
                          ]
                        }
                        """);
        // When
        Vulnerability v = PhpAdvisories.toVulnerability(advisory).orElseThrow();
        // Then
        assertThat(v.cve(), is("CVE-2026-93682"));
        assertThat(v.ghsa(), is("GHSA-7875-c8px-7q5f"));
        assertThat(v.name(), is("Out-of-bounds read in the HTTP stream wrapper"));
        assertThat(v.description(), is("An OOB read in the wrapper when following a redirect."));
        assertThat(v.severity(), is("medium"));
        assertThat(v.cvss(), is(5.3));
        assertThat(v.component(), is("ext-standard"));
        assertThat(v.published(), is("2026-09-24"));
        assertThat(v.source(), is(PhpAdvisories.SOURCE_GENERATED));
        assertThat(v.affected().stream().map(r -> r.introduced()).toList(), contains("0", "8.3.0"));
        assertThat(
                v.affected().stream().map(r -> r.fixed()).toList(), contains("8.2.34", "8.3.35"));
        assertThat(v.affected().get(0).assumed(), is(true));
        assertThat(v.affected().get(1).assumed(), is(false));
        assertThat(
                v.links(),
                contains(
                        "https://github.com/php/php-src/security/advisories/GHSA-7875-c8px-7q5f",
                        "https://nvd.nist.gov/vuln/detail/CVE-2026-93682",
                        "https://www.php.net/ChangeLog-8.php#8.2.34",
                        "https://www.php.net/ChangeLog-8.php#8.3.35"));
    }

    @Test
    void shouldLeaveComponentNullForPhpItself() throws Exception {
        // Given
        JsonNode advisory =
                MAPPER.readTree(
                        base("\"cve_id\": \"CVE-2026-1\", \"withdrawn_at\": null", "php-src"));
        // When
        Vulnerability v = PhpAdvisories.toVulnerability(advisory).orElseThrow();
        // Then
        assertThat(v.component(), is(nullValue()));
        assertThat(v.cvss(), is(nullValue()));
    }

    @Test
    void shouldSkipAdvisoriesWithoutCveOrWithdrawn() throws Exception {
        assertThat(
                PhpAdvisories.toVulnerability(
                        MAPPER.readTree(base("\"cve_id\": null, \"withdrawn_at\": null", ""))),
                is(Optional.empty()));
        assertThat(
                PhpAdvisories.toVulnerability(
                        MAPPER.readTree(
                                base(
                                        "\"cve_id\": \"CVE-2026-1\", \"withdrawn_at\": \"2026-02-02T00:00:00Z\"",
                                        ""))),
                is(Optional.empty()));
    }

    @Test
    void shouldFailOnUnknownSeverity() throws Exception {
        JsonNode advisory =
                MAPPER.readTree(
                        base("\"cve_id\": \"CVE-2026-1\", \"withdrawn_at\": null", "")
                                .replace("\"severity\": \"low\"", "\"severity\": \"moderate\""));
        assertThrows(IllegalArgumentException.class, () -> PhpAdvisories.toVulnerability(advisory));
    }

    private static String base(String idFields, String packageName) {
        return "{ \"ghsa_id\": \"GHSA-a\", "
                + idFields
                + ", \"state\": \"published\", \"severity\": \"low\", \"html_url\": \"u\", \"summary\": \"s\","
                + " \"published_at\": \"2026-01-01T00:00:00Z\", \"vulnerabilities\": [ { \"package\": { \"name\": \""
                + packageName
                + "\" }, \"vulnerable_version_range\": \"< 8.3.1\", \"patched_versions\": \"8.3.1\" } ] }";
    }
}
