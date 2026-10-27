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
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.lessThan;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.zaproxy.zap.extension.pscanrules.KnownVulnerabilities.VersionRange;
import org.zaproxy.zap.extension.pscanrules.KnownVulnerabilities.Vulnerability;

class KnownVulnerabilitiesUpdaterUnitTest {

    private static final LocalDate TODAY = LocalDate.of(2026, 10, 22);

    @TempDir Path tempDir;

    @Test
    void shouldMergeNewestFirstThenByCveAndAppendManualEntries() {
        // Given
        Vulnerability older = generated("CVE-2024-0002", "2024-01-01");
        Vulnerability newer = generated("CVE-2024-0001", "2025-01-01");
        Vulnerability sameDay = generated("CVE-2024-0003", "2025-01-01");
        Vulnerability manual = manual("CVE-2019-11043");
        KnownVulnerabilities existing =
                new KnownVulnerabilities(List.of("c"), 1, "2026-01-01", List.of(manual));
        // When
        KnownVulnerabilities merged =
                KnownVulnerabilitiesUpdater.merge(existing, List.of(older, sameDay, newer), TODAY);
        // Then
        assertThat(
                merged.vulnerabilities().stream().map(Vulnerability::cve).toList(),
                contains("CVE-2024-0001", "CVE-2024-0003", "CVE-2024-0002", "CVE-2019-11043"));
        assertThat(merged.comment(), contains("c"));
        assertThat(merged.schemaVersion(), is(1));
        assertThat(merged.lastUpdated(), is("2026-10-22"));
    }

    @Test
    void shouldDropManualEntriesCoveredByGeneratedOnes() {
        // Given
        KnownVulnerabilities existing =
                new KnownVulnerabilities(
                        null,
                        null,
                        "2026-01-01",
                        List.of(manual("CVE-2024-0001"), manual("CVE-2024-0009")));
        // When
        KnownVulnerabilities merged =
                KnownVulnerabilitiesUpdater.merge(
                        existing, List.of(generated("CVE-2024-0001", "2025-01-01")), TODAY);
        // Then
        assertThat(
                merged.vulnerabilities().stream().map(Vulnerability::cve).toList(),
                contains("CVE-2024-0001", "CVE-2024-0009"));
        assertThat(merged.vulnerabilities().get(0).source(), is(PhpAdvisories.SOURCE_GENERATED));
        assertThat(merged.schemaVersion(), is(1));
    }

    @Test
    void shouldKeepLastUpdatedWhenVulnerabilitiesUnchanged() {
        // Given
        Vulnerability generated = generated("CVE-2024-0001", "2025-01-01");
        Vulnerability manual = manual("CVE-2019-11043");
        KnownVulnerabilities existing =
                new KnownVulnerabilities(null, 1, "2026-01-01", List.of(generated, manual));
        // When
        KnownVulnerabilities merged =
                KnownVulnerabilitiesUpdater.merge(existing, List.of(generated), TODAY);
        // Then
        assertThat(merged.lastUpdated(), is("2026-01-01"));
        assertThat(merged.vulnerabilities(), is(existing.vulnerabilities()));
    }

    @Test
    void shouldUpdateLastUpdatedWhenVulnerabilitiesChanged() {
        // Given
        KnownVulnerabilities existing =
                new KnownVulnerabilities(
                        null, 1, "2026-01-01", List.of(generated("CVE-2024-0001", "2025-01-01")));
        // When
        KnownVulnerabilities merged =
                KnownVulnerabilitiesUpdater.merge(
                        existing,
                        List.of(
                                generated("CVE-2024-0001", "2025-01-01"),
                                generated("CVE-2024-0002", "2026-01-01")),
                        TODAY);
        // Then
        assertThat(merged.lastUpdated(), is("2026-10-22"));
    }

    @Test
    void shouldWriteJsonTheLoaderReads() throws Exception {
        // Given
        KnownVulnerabilities vulnerabilities =
                new KnownVulnerabilities(
                        List.of("line 1", "line 2"),
                        1,
                        "2026-10-22",
                        List.of(
                                new Vulnerability(
                                        "CVE-2024-0001",
                                        "GHSA-a",
                                        "Name & <co>",
                                        "Desc",
                                        "high",
                                        null,
                                        null,
                                        List.of(
                                                new VersionRange("0", "8.1.29", true),
                                                new VersionRange("8.2.0", "8.2.20", false),
                                                new VersionRange("9.0.0", null, false)),
                                        List.of("https://example.com/1"),
                                        "2025-01-01",
                                        PhpAdvisories.SOURCE_GENERATED)));
        // When
        String json = KnownVulnerabilitiesUpdater.toJson(vulnerabilities);
        // Then
        assertThat(
                json,
                containsString(
                        "{\n  \"_comment\": [\n    \"line 1\",\n    \"line 2\"\n  ],\n  \"schemaVersion\": 1,\n  \"lastUpdated\": \"2026-10-22\",\n  \"vulnerabilities\": [\n"));
        assertThat(
                json,
                containsString(
                        "\"introduced\": \"0\",\n          \"fixed\": \"8.1.29\",\n          \"assumed\": true\n"));
        assertThat(
                json,
                containsString("\"introduced\": \"8.2.0\",\n          \"fixed\": \"8.2.20\"\n"));
        assertThat(json, containsString("\"fixed\": null"));
        assertThat(json, not(containsString("cvss")));
        assertThat(json, not(containsString("component")));
        assertThat(json, not(containsString("\"assumed\": false")));
        assertThat(json.indexOf("\"cve\""), is(lessThan(json.indexOf("\"ghsa\""))));
        assertThat(json, containsString("\"source\": \"github-advisories\"\n"));
        Path file = Files.writeString(tempDir.resolve("v.json"), json);
        assertThat(KnownVulnerabilities.load(file), is(vulnerabilities));
    }

    @Test
    void shouldRenderHelpPageMostSevereFirstWithAnchors() throws Exception {
        // Given
        String page =
                "<HTML>\n<BODY>\nIntro.<br>\nLast updated: <wbr pscan-data=\"lastUpdated\" />. "
                        + "Vulnerabilities listed: <wbr pscan-data='count'>.\n\n"
                        + "<wbr  pscan-data=\"vulnerabilities\"/>\n</BODY>\n</HTML>\n";
        // When
        String html =
                KnownVulnerabilitiesUpdater.toHelpHtml(page, entryTemplate(), vulnerabilities());
        // Then
        assertThat(
                html,
                containsString(
                        "<HTML>\n<BODY>\nIntro.<br>\nLast updated: 2026-10-21. Vulnerabilities listed: 2.\n\n<H2 id="));
        assertThat(
                html.indexOf("<H2 id=\"cve-2019-11043\">CVE-2019-11043 (Critical)</H2>"),
                is(lessThan(html.indexOf("<H2 id=\"cve-2024-0001\">CVE-2024-0001 (Medium)</H2>"))));
        assertThat(html, containsString("<b>Medium &lt;one&gt;</b>"));
        assertThat(html, containsString("A &amp; B"));
        assertThat(
                html,
                containsString(
                        "all versions before 8.1.29 (assumed, not confirmed by the advisory)<br>8.2.0 and later, before 8.2.20"));
        assertThat(html, containsString("<td>CVSS score:</td><td>5.3</td>"));
        assertThat(html, containsString("<td>Component:</td><td>ext-soap</td>"));
        assertThat(
                html,
                containsString("<li><a href=\"https://example.com/2\">https://example.com/2</a>"));
        assertThat(html, endsWith("</ul>\n\n\n</BODY>\n</HTML>\n"));
        assertThat(html, not(containsString("<wbr")));
    }

    @Test
    void shouldFailToRenderHelpPageWithoutVulnerabilitiesTag() {
        // Given
        String page = "<BODY>Last updated: <wbr pscan-data=\"lastUpdated\" />.</BODY>";
        KnownVulnerabilities vulnerabilities = vulnerabilities();
        // When / Then
        IllegalArgumentException e =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> KnownVulnerabilitiesUpdater.toHelpHtml(page, "", vulnerabilities));
        assertThat(e.getMessage(), containsString("vulnerabilities"));
    }

    @Test
    void shouldFailToRenderHelpPageWithUnknownTag() {
        // Given
        String page =
                "<BODY><wbr pscan-data=\"vulnerabilities\" /><wbr pscan-data=\"total\" /></BODY>";
        KnownVulnerabilities vulnerabilities = vulnerabilities();
        // When / Then
        IllegalArgumentException e =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> KnownVulnerabilitiesUpdater.toHelpHtml(page, "", vulnerabilities));
        assertThat(e.getMessage(), containsString("<wbr pscan-data=\"total\" />"));
    }

    @Test
    void shouldLeaveOtherWbrTagsInHelpPage() {
        // Given
        String page = "<BODY>a<wbr>b<wbr pscan-data=\"vulnerabilities\" /></BODY>";
        // When
        String html = KnownVulnerabilitiesUpdater.toHelpHtml(page, "", KnownVulnerabilities.EMPTY);
        // Then
        assertThat(html, is("<BODY>a<wbr>b</BODY>"));
    }

    private static KnownVulnerabilities vulnerabilities() {
        return new KnownVulnerabilities(
                null,
                1,
                "2026-10-21",
                List.of(
                        new Vulnerability(
                                "CVE-2024-0001",
                                "GHSA-a",
                                "Medium <one>",
                                "A & B",
                                "medium",
                                5.3,
                                "ext-soap",
                                List.of(
                                        new VersionRange("0", "8.1.29", true),
                                        new VersionRange("8.2.0", "8.2.20", false)),
                                List.of("https://example.com/1"),
                                "2024-01-01",
                                PhpAdvisories.SOURCE_GENERATED),
                        manual("CVE-2019-11043")));
    }

    private static String entryTemplate() throws Exception {
        return KnownVulnerabilitiesUpdater.readResource(
                KnownVulnerabilitiesUpdater.HELP_ENTRY_TEMPLATE_RESOURCE);
    }

    @Test
    void shouldRenderTemplatePlaceholders() {
        assertThat(
                KnownVulnerabilitiesUpdater.render(
                        "<b>{{a}}</b> {{b}} {{a}} {{c}}", Map.of("a", "1", "b", "2")),
                is("<b>1</b> 2 1 {{c}}"));
    }

    @Test
    void shouldHaveHelpEntryTemplateWithPlaceholders() throws Exception {
        // Given / When
        String template = entryTemplate();
        // Then
        for (String placeholder :
                List.of(
                        "anchor",
                        "cve",
                        "severity",
                        "name",
                        "description",
                        "details",
                        "affected",
                        "references")) {
            assertThat(placeholder, template, containsString("{{" + placeholder + "}}"));
        }
    }

    @Test
    void shouldDescribeRanges() {
        assertThat(
                KnownVulnerabilitiesUpdater.rangeText(new VersionRange("8.1.0", "8.1.29", false)),
                is("8.1.0 and later, before 8.1.29"));
        assertThat(
                KnownVulnerabilitiesUpdater.rangeText(new VersionRange("1.0", null, false)),
                is("1.0 and later, no fix available"));
        assertThat(KnownVulnerabilitiesUpdater.anchor("CVE-2024-4577"), is("cve-2024-4577"));
    }

    @Test
    void shouldParseNextLink() {
        assertThat(
                KnownVulnerabilitiesUpdater.nextLink(
                        "<https://api.github.com/x?page=2>; rel=\"next\", <https://api.github.com/x?page=3>; rel=\"last\""),
                is("https://api.github.com/x?page=2"));
        assertThat(
                KnownVulnerabilitiesUpdater.nextLink(
                        "<https://api.github.com/x?page=1>; rel=\"prev\""),
                is(nullValue()));
        assertThat(KnownVulnerabilitiesUpdater.nextLink(null), is(nullValue()));
    }

    private static Vulnerability generated(String cve, String published) {
        return new Vulnerability(
                cve,
                "GHSA-" + cve,
                "Name " + cve,
                "Description",
                "high",
                7.5,
                null,
                List.of(new VersionRange("8.1.0", "8.1.29", false)),
                List.of("https://example.com/" + cve),
                published,
                PhpAdvisories.SOURCE_GENERATED);
    }

    private static Vulnerability manual(String cve) {
        return new Vulnerability(
                cve,
                null,
                "Old one",
                "Old description",
                "critical",
                9.8,
                null,
                List.of(new VersionRange("7.3.0", "7.3.11", false)),
                List.of("https://example.com/2"),
                null,
                KnownVulnerabilitiesUpdater.SOURCE_MANUAL);
    }
}
