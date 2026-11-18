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

import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;
import org.zaproxy.zap.extension.pscanrules.AdvisoryUtils.ParsedRange;
import org.zaproxy.zap.extension.pscanrules.KnownVulnerabilities.Severity;
import org.zaproxy.zap.extension.pscanrules.KnownVulnerabilities.Vulnerability;

/**
 * Converts the security advisories listed on the nginx.org page {@link #ADVISORIES_URL} into {@link
 * Vulnerability vulnerabilities}. The page gives, for each issue, a title, a severity, the
 * vulnerable version ranges (first to last vulnerable release, inclusive) and the releases which
 * are not vulnerable ({@code 1.27.0+, 1.26.1+}, the first fixed release of each line). It has no
 * description or publication date, so those come from the CVE record of each issue.
 *
 * <p>The vulnerable ranges span the lines which were patched, e.g. {@code 1.1.3-1.23.1} for an
 * issue fixed in the stable line from {@code 1.22.1}, so the patched releases of each stable line
 * are removed from them.
 */
final class NginxAdvisories {

    static final String SOURCE_GENERATED = "nginx-advisories";
    static final String ADVISORIES_URL = "https://nginx.org/en/security_advisories.html";
    static final String CVE_API_URL = "https://cveawg.mitre.org/api/cve/";

    private static final Pattern ENTRY = Pattern.compile("<li><p>(.*?)</p></li>", Pattern.DOTALL);
    private static final String BREAK = "(?i)<br\\s*/?>";
    private static final Pattern VULNERABLE_FIELD = Pattern.compile(BREAK + "\\s*Vulnerable:");
    private static final Pattern TAG = Pattern.compile("<[^>]*>");
    private static final Pattern LINK =
            Pattern.compile("<a href=\"([^\"]+)\">([^<]*)</a>", Pattern.CASE_INSENSITIVE);

    /**
     * The identifier of an advisory, a CVE or one from another source such as {@code
     * CORE-2010-0121}. The page has had a doubled {@code CVE-CVE-} prefix.
     */
    private static final Pattern ID = Pattern.compile("^(?:CVE-)?((?:CVE|CORE)-\\d{4}-\\d{3,})$");

    private static final Pattern VERSION = Pattern.compile("\\d{1,6}\\.\\d{1,6}\\.\\d{1,6}");
    private static final Pattern FIXED = Pattern.compile("^(\\d+\\.\\d+\\.\\d+)\\+$");
    private static final Pattern WINDOWS = Pattern.compile("^nginx/Windows\\s+");

    /** The project's own ratings; the issues rated {@code none} are not vulnerabilities. */
    private static final Map<String, Severity> SEVERITIES =
            Map.of(
                    "minor", Severity.LOW,
                    "low", Severity.LOW,
                    "medium", Severity.MEDIUM,
                    "major", Severity.HIGH);

    private static final String SEVERITY_NONE = "none";

    /**
     * An advisory as listed on the page.
     *
     * @param id the CVE, or the identifier of the advisory when it has none
     * @param title the title
     * @param severity the project's severity rating
     * @param advisoryUrl the project's own advisory, {@code null} if none
     * @param vulnerable the vulnerable versions, e.g. {@code 1.25.0-1.25.5, 1.26.0}
     * @param notVulnerable the versions which are not vulnerable, e.g. {@code 1.27.0+, 1.26.1+}
     */
    record Advisory(
            String id,
            String title,
            String severity,
            String advisoryUrl,
            String vulnerable,
            String notVulnerable) {

        boolean hasCve() {
            return KnownVulnerabilities.isCve(id);
        }
    }

    private NginxAdvisories() {}

    /**
     * Parses the advisories page.
     *
     * @param html the page
     * @return the advisories, in page order
     * @throws IllegalArgumentException if an entry cannot be understood, so that changes to the
     *     page are noticed rather than silently dropped
     */
    static List<Advisory> parse(String html) {
        List<Advisory> advisories =
                ENTRY.matcher(html).results().map(m -> parseEntry(m.group(1))).toList();
        // Every entry has a "Vulnerable:" field, so a difference means entries were not matched.
        long expected = VULNERABLE_FIELD.matcher(html).results().count();
        if (advisories.isEmpty() || advisories.size() != expected) {
            throw new IllegalArgumentException(
                    "Parsed " + advisories.size() + " advisories but the page has " + expected);
        }
        return advisories;
    }

    private static Advisory parseEntry(String entry) {
        String[] fields = entry.split(BREAK);
        String title = text(fields[0]);
        String severity = null;
        String vulnerable = null;
        String notVulnerable = null;
        for (String field : fields) {
            String value = text(field);
            if (value.startsWith("Severity:")) {
                severity = value.substring("Severity:".length()).trim().toLowerCase(Locale.ROOT);
            } else if (value.startsWith("Not vulnerable:")) {
                notVulnerable = value.substring("Not vulnerable:".length()).trim();
            } else if (value.startsWith("Vulnerable:")) {
                vulnerable = value.substring("Vulnerable:".length()).trim();
            }
        }
        String id = null;
        String advisoryUrl = null;
        String idUrl = null;
        Matcher link = LINK.matcher(entry);
        while (link.find()) {
            String linkText = link.group(2).trim();
            Matcher idMatcher = ID.matcher(linkText);
            if (idMatcher.matches()) {
                if (id == null) {
                    id = idMatcher.group(1);
                    idUrl = link.group(1);
                }
            } else if ("Advisory".equals(linkText) && advisoryUrl == null) {
                advisoryUrl = link.group(1);
            }
        }
        if (id == null || severity == null || vulnerable == null || notVulnerable == null) {
            throw new IllegalArgumentException("Cannot parse the advisory: " + title);
        }
        // An advisory by another party, e.g. CORE-2010-0121, is linked with its ID as the text.
        if (advisoryUrl == null && !KnownVulnerabilities.isCve(id)) {
            advisoryUrl = idUrl;
        }
        return new Advisory(id, title, severity, advisoryUrl, vulnerable, notVulnerable);
    }

    /**
     * Converts an advisory, returning empty when it is rated {@code none} by the project, which is
     * the case of issues which are not vulnerabilities, e.g. unsanitised error log data.
     *
     * @param advisory the advisory
     * @param cveRecord the CVE record of the advisory in CVE JSON 5 format, {@code null} if it has
     *     none or it is not published
     * @return the vulnerability, or empty
     * @throws IllegalArgumentException if the advisory cannot be understood
     */
    static Optional<Vulnerability> toVulnerability(Advisory advisory, JsonNode cveRecord) {
        String id = advisory.id();
        if (SEVERITY_NONE.equals(advisory.severity())) {
            System.out.printf("Skipping %s, its severity is none: %s%n", id, advisory.title());
            return Optional.empty();
        }
        Severity severity = SEVERITIES.get(advisory.severity());
        if (severity == null) {
            throw new IllegalArgumentException(id + ": unknown severity " + advisory.severity());
        }

        List<ParsedRange> ranges = AdvisoryUtils.sorted(ranges(advisory), id);

        JsonNode cna = cveRecord == null ? null : cveRecord.path("containers").path("cna");
        List<String> links = new ArrayList<>();
        if (advisory.advisoryUrl() != null) {
            links.add(advisory.advisoryUrl());
        }
        links.add(ADVISORIES_URL);
        if (advisory.hasCve()) {
            links.add("https://www.cve.org/CVERecord?id=" + id);
            links.add("https://nvd.nist.gov/vuln/detail/" + id);
        }
        return Optional.of(
                new Vulnerability(
                        id,
                        null,
                        advisory.title(),
                        cna == null ? "" : AdvisoryUtils.firstParagraph(description(cna)),
                        severity.getKey(),
                        cna == null ? null : cvss(cna),
                        null,
                        ranges.stream().map(ParsedRange::toVersionRange).toList(),
                        links,
                        cna == null ? null : published(cveRecord, cna),
                        SOURCE_GENERATED));
    }

    /**
     * The affected ranges: each stated range, first to last vulnerable release, ends before the
     * release after the last, and has the patched releases of the stable lines (the fixed versions
     * within it) removed. Windows only issues cannot be told from the {@code Server} header so
     * their ranges are assumed.
     */
    private static List<ParsedRange> ranges(Advisory advisory) {
        String id = advisory.id();
        boolean windows = WINDOWS.matcher(advisory.vulnerable()).find();
        List<String> fixed = new ArrayList<>();
        for (String part : advisory.notVulnerable().split(",\\s*")) {
            Matcher m = FIXED.matcher(part.trim());
            if (!m.matches()) {
                throw new IllegalArgumentException(id + ": unexpected fixed version " + part);
            }
            fixed.add(m.group(1));
        }

        List<ParsedRange> ranges = new ArrayList<>();
        for (String part : WINDOWS.matcher(advisory.vulnerable()).replaceFirst("").split(",\\s*")) {
            String[] bounds = part.trim().split("-", -1);
            if (bounds.length > 2 || !Stream.of(bounds).allMatch(NginxAdvisories::isVersion)) {
                throw new IllegalArgumentException(id + ": unexpected vulnerable versions " + part);
            }
            ranges.add(
                    new ParsedRange(
                            bounds[0],
                            AdvisoryUtils.bumpPatch(bounds[bounds.length - 1]),
                            windows,
                            true,
                            false));
        }

        for (String patched : fixed) {
            ranges = removePatchedLine(ranges, patched);
        }
        for (ParsedRange range : ranges) {
            if (fixed.stream()
                    .noneMatch(f -> KnownVulnerabilities.compareVersions(f, range.fixed()) >= 0)) {
                System.out.printf(
                        "WARNING: %s is fixed in %s but a vulnerable range ends after that.%n",
                        id, fixed);
            }
        }
        return ranges;
    }

    /**
     * Removes the releases of the line of the patched version, from it on, e.g. {@code 1.22.1} up
     * to {@code 1.23.0}, from the ranges which include it.
     */
    private static List<ParsedRange> removePatchedLine(List<ParsedRange> ranges, String patched) {
        String lineEnd = AdvisoryUtils.nextBranchStart(patched);
        List<ParsedRange> result = new ArrayList<>();
        for (ParsedRange range : ranges) {
            if (KnownVulnerabilities.compareVersions(patched, range.introduced()) > 0
                    && KnownVulnerabilities.compareVersions(patched, range.fixed()) < 0) {
                result.add(
                        new ParsedRange(range.introduced(), patched, range.assumed(), true, false));
                if (KnownVulnerabilities.compareVersions(lineEnd, range.fixed()) < 0) {
                    result.add(
                            new ParsedRange(lineEnd, range.fixed(), range.assumed(), true, false));
                }
            } else {
                result.add(range);
            }
        }
        return result;
    }

    private static boolean isVersion(String version) {
        return VERSION.matcher(version).matches();
    }

    private static String description(JsonNode cna) {
        return stream(cna.path("descriptions"))
                .filter(d -> d.path("lang").asText("").startsWith("en"))
                .map(d -> d.path("value").asText(""))
                .findFirst()
                .orElse("");
    }

    /** The base score of the first CVSS metric, newest version first, {@code null} if none. */
    private static Double cvss(JsonNode cna) {
        return Stream.of("cvssV4_0", "cvssV3_1", "cvssV3_0")
                .flatMap(
                        version ->
                                stream(cna.path("metrics"))
                                        .map(m -> m.path(version).path("baseScore")))
                .filter(JsonNode::isNumber)
                .map(JsonNode::asDouble)
                .findFirst()
                .orElse(null);
    }

    /** The date part of the publication date of the record, else of the public date. */
    private static String published(JsonNode cveRecord, JsonNode cna) {
        return Stream.of(
                        cveRecord.path("cveMetadata").path("datePublished").asText(""),
                        cna.path("datePublic").asText(""))
                .filter(d -> d.length() >= 10)
                .map(d -> d.substring(0, 10))
                .findFirst()
                .orElse(null);
    }

    private static Stream<JsonNode> stream(JsonNode array) {
        return array.isArray() ? StreamSupport.stream(array.spliterator(), false) : Stream.empty();
    }

    /** The text of the HTML fragment, without tags and with the common entities decoded. */
    private static String text(String html) {
        return TAG.matcher(html)
                .replaceAll("")
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&quot;", "\"")
                .replace("&#39;", "'")
                .replace("&amp;", "&")
                .replaceAll("\\s+", " ")
                .trim();
    }
}
