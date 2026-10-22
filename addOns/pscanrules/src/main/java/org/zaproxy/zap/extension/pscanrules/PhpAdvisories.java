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
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.zaproxy.zap.extension.pscanrules.KnownVulnerabilities.Severity;
import org.zaproxy.zap.extension.pscanrules.KnownVulnerabilities.VersionRange;
import org.zaproxy.zap.extension.pscanrules.KnownVulnerabilities.Vulnerability;

/**
 * Converts the published security advisories of php/php-src, as returned by the GitHub REST API,
 * into {@link Vulnerability} entries. Used by {@link KnownVulnerabilitiesUpdater}, not at scan
 * time.
 *
 * <p>The methods are pure so that they can be unit tested without network access.
 */
final class PhpAdvisories {

    static final String SOURCE_GENERATED = "github-advisories";
    static final String API_URL =
            "https://api.github.com/repos/php/php-src/security-advisories?state=published&per_page=100";
    private static final int MAX_DESCRIPTION_LENGTH = 500;

    /** Paragraphs shorter than this are greetings or similar noise rather than a description. */
    private static final int MIN_PARAGRAPH_LENGTH = 30;

    private static final List<String> PREFERRED_SECTIONS = List.of("summary", "impact");
    private static final Set<String> PHP_ITSELF = Set.of("php", "php-src");
    private static final Pattern VERSION = Pattern.compile("\\d+(?:\\.\\d+)*");
    private static final Pattern LESS_THAN = Pattern.compile("^<(?!=)\\s*(\\S+)$");
    private static final Pattern LESS_THAN_OR_EQUAL = Pattern.compile("^<=\\s*(\\S+)$");
    private static final Pattern BOUNDED =
            Pattern.compile("^(>=?)\\s*(\\S+)\\s*,\\s*(<=?)\\s*(\\S+)$");
    private static final Pattern HYPHENATED = Pattern.compile("^(\\S+)\\s*-\\s*(\\S+)$");
    private static final Pattern MARKDOWN_LINK = Pattern.compile("\\[([^]]*)]\\([^)]*\\)");
    private static final Pattern MARKDOWN_EMPHASIS = Pattern.compile("[`*]");
    private static final Pattern WHITESPACE = Pattern.compile("\\s+");

    /**
     * A range parsed from an advisory, {@code introduced <= version < fixed}.
     *
     * @param introduced the first affected version
     * @param fixed the first fixed version
     * @param assumed whether the lower bound was not stated by the advisory and has been assumed
     * @param fixedKnown whether the fixed version was stated by the advisory rather than computed
     * @param openLowerBound whether the advisory gave no lower bound ({@code < X} or {@code <= X})
     */
    record ParsedRange(
            String introduced,
            String fixed,
            boolean assumed,
            boolean fixedKnown,
            boolean openLowerBound) {

        ParsedRange(String introduced, String fixed, boolean openLowerBound) {
            this(introduced, fixed, false, true, openLowerBound);
        }

        ParsedRange withFixedKnown(List<String> patchedVersions) {
            return new ParsedRange(
                    introduced, fixed, assumed, patchedVersions.contains(fixed), openLowerBound);
        }

        VersionRange toVersionRange() {
            return new VersionRange(introduced, fixed, assumed);
        }
    }

    private PhpAdvisories() {}

    /**
     * Converts one advisory, returning empty when it should be skipped: not published, withdrawn,
     * or without a CVE.
     *
     * @param advisory the advisory as returned by the GitHub REST API
     * @return the vulnerability, or empty
     * @throws IllegalArgumentException if the advisory cannot be understood, so that new formats
     *     are noticed rather than silently dropped
     */
    static Optional<Vulnerability> toVulnerability(JsonNode advisory) {
        if (!"published".equals(advisory.path("state").asText())
                || !advisory.path("withdrawn_at").isNull()) {
            return Optional.empty();
        }
        String cve = text(advisory, "cve_id");
        if (cve == null || cve.isBlank()) {
            return Optional.empty();
        }
        String ghsa = text(advisory, "ghsa_id");
        if (ghsa == null) {
            throw new IllegalArgumentException("Advisory without ghsa_id: " + cve);
        }
        String severity =
                Optional.ofNullable(text(advisory, "severity")).orElse("").toLowerCase(Locale.ROOT);
        if (Stream.of(Severity.values()).noneMatch(s -> s.getKey().equals(severity))) {
            throw new IllegalArgumentException(ghsa + ": unknown severity '" + severity + "'");
        }

        List<JsonNode> packages = new ArrayList<>();
        advisory.path("vulnerabilities").forEach(packages::add);
        List<ParsedRange> ranges =
                packages.stream()
                        .flatMap(
                                pkg ->
                                        parseVersionRanges(
                                                Optional.ofNullable(
                                                                text(
                                                                        pkg,
                                                                        "vulnerable_version_range"))
                                                        .orElse(""),
                                                text(pkg, "patched_versions"))
                                                .stream())
                        .toList();
        if (ranges.isEmpty()) {
            throw new IllegalArgumentException(ghsa + ": no version ranges");
        }
        List<ParsedRange> affected = consolidate(ranges, ghsa);

        List<String> links = new ArrayList<>();
        links.add(
                Optional.ofNullable(text(advisory, "html_url"))
                        .orElse("https://github.com/php/php-src/security/advisories/" + ghsa));
        links.add("https://nvd.nist.gov/vuln/detail/" + cve);
        affected.stream()
                .filter(ParsedRange::fixedKnown)
                .map(ParsedRange::fixed)
                .sorted(KnownVulnerabilities::compareVersions)
                .forEach(
                        fixed ->
                                links.add(
                                        "https://www.php.net/ChangeLog-"
                                                + fixed.substring(0, fixed.indexOf('.'))
                                                + ".php#"
                                                + fixed));

        return Optional.of(
                new Vulnerability(
                        cve,
                        ghsa,
                        Optional.ofNullable(text(advisory, "summary")).orElse("").trim(),
                        firstParagraph(
                                Optional.ofNullable(text(advisory, "description")).orElse("")),
                        severity,
                        cvssScore(advisory),
                        packages.stream()
                                .map(pkg -> text(pkg.path("package"), "name"))
                                .filter(name -> name != null && !name.isBlank())
                                .filter(name -> !PHP_ITSELF.contains(name.toLowerCase(Locale.ROOT)))
                                .findFirst()
                                .orElse(null),
                        affected.stream().map(ParsedRange::toVersionRange).toList(),
                        links,
                        Optional.ofNullable(text(advisory, "published_at"))
                                .map(d -> d.contains("T") ? d.substring(0, d.indexOf('T')) : d)
                                .orElse(""),
                        SOURCE_GENERATED));
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.path(field);
        return value.isTextual() ? value.asText() : null;
    }

    private static Double cvssScore(JsonNode advisory) {
        JsonNode severities = advisory.path("cvss_severities");
        return Stream.of("cvss_v3", "cvss_v4")
                .map(key -> severities.path(key).path("score"))
                .filter(score -> score.isNumber() && score.asDouble() > 0)
                .map(JsonNode::asDouble)
                .findFirst()
                .orElse(null);
    }

    /**
     * Parses the free text {@code vulnerable_version_range} of one vulnerability entry. The formats
     * handled are those seen in the php-src advisories; anything else fails so that new formats get
     * noticed.
     *
     * @param range the range text, e.g. {@code < 8.2.35}
     * @param patched the {@code patched_versions} text, may be {@code null}
     * @return the parsed ranges, one per comma separated part
     */
    static List<ParsedRange> parseVersionRanges(String range, String patched) {
        List<String> patchedVersions = normalizePatched(patched);
        String text = range.trim();
        if (text.contains(",") && !BOUNDED.matcher(text).matches()) {
            return Arrays.stream(text.split(","))
                    .flatMap(part -> parseVersionRanges(part, patched).stream())
                    .toList();
        }

        Matcher m = LESS_THAN.matcher(text);
        if (m.matches()) {
            String upper = version(m.group(1));
            return List.of(
                    new ParsedRange(branchStart(upper), fixed(upper, patchedVersions, upper), true)
                            .withFixedKnown(patchedVersions));
        }
        m = LESS_THAN_OR_EQUAL.matcher(text);
        if (m.matches()) {
            String last = version(m.group(1));
            return List.of(
                    new ParsedRange(
                                    branchStart(last),
                                    fixed(last, patchedVersions, bumpPatch(last)),
                                    true)
                            .withFixedKnown(patchedVersions));
        }
        m = BOUNDED.matcher(text);
        if (m.matches()) {
            String lower = version(m.group(2));
            String upper = version(m.group(4));
            String introduced = ">".equals(m.group(1)) ? bumpPatch(lower) : lower;
            String fixed = "<".equals(m.group(3)) ? upper : bumpPatch(upper);
            return List.of(
                    new ParsedRange(introduced, fixed(upper, patchedVersions, fixed), false)
                            .withFixedKnown(patchedVersions));
        }
        m = HYPHENATED.matcher(text);
        if (m.matches()) {
            String lower = version(m.group(1));
            String last = version(m.group(2));
            return List.of(
                    new ParsedRange(lower, fixed(last, patchedVersions, bumpPatch(last)), false)
                            .withFixedKnown(patchedVersions));
        }
        if (VERSION.matcher(text).matches()) {
            return List.of(
                    new ParsedRange(text, fixed(text, patchedVersions, bumpPatch(text)), false)
                            .withFixedKnown(patchedVersions));
        }
        throw new IllegalArgumentException("Unrecognised version range: '" + range + "'");
    }

    /**
     * Prefers the stated patched version from the same branch as {@code upper}, else {@code
     * computed}.
     */
    private static String fixed(String upper, List<String> patchedVersions, String computed) {
        return patchedVersions.stream()
                .filter(p -> branchStart(p).equals(branchStart(upper)))
                .findFirst()
                .orElse(computed);
    }

    private static String version(String text) {
        if (!VERSION.matcher(text).matches()) {
            throw new IllegalArgumentException("Not a version: '" + text + "'");
        }
        return text;
    }

    /**
     * Splits and cleans {@code patched_versions}, which has been seen as empty, {@code " 8.1.28"}
     * and {@code "8.1.29, 8.2.20, 8.3.8."}.
     */
    static List<String> normalizePatched(String patched) {
        if (patched == null) {
            return List.of();
        }
        return VERSION.matcher(patched).results().map(MatchResultText::of).toList();
    }

    /** Helper to turn match results into their text, keeping the stream pipeline readable. */
    private static final class MatchResultText {
        private static String of(java.util.regex.MatchResult result) {
            return result.group();
        }
    }

    /** The first version of the branch, e.g. {@code 8.1.0} for {@code 8.1.29}. */
    static String branchStart(String version) {
        String[] parts = version.split("\\.");
        return parts[0] + "." + (parts.length > 1 ? parts[1] : "0") + ".0";
    }

    /** Whether the version is the first of its branch, e.g. {@code 8.1.0} or {@code 8.1}. */
    static boolean isBranchStart(String version) {
        String[] parts = version.split("\\.");
        return parts.length == 2 || parts.length == 3 && "0".equals(parts[2]);
    }

    /** The version with the patch component incremented, e.g. {@code 8.1.30} for {@code 8.1.29}. */
    static String bumpPatch(String version) {
        String[] parts = version.split("\\.");
        long major = Long.parseLong(parts[0]);
        long minor = parts.length > 1 ? Long.parseLong(parts[1]) : 0;
        long patch = parts.length > 2 ? Long.parseLong(parts[2]) : 0;
        return major + "." + minor + "." + (patch + 1);
    }

    /**
     * Sorts the ranges, fails on overlaps, and extends the lowest range down to version 0 when the
     * advisory gave it no lower bound or a lower bound which is just the start of a branch, since
     * older end-of-life branches are almost always affected too but are never listed.
     *
     * @param ranges the ranges of one advisory
     * @param id the advisory ID, for error messages
     * @return the consolidated ranges, lowest first
     */
    static List<ParsedRange> consolidate(List<ParsedRange> ranges, String id) {
        List<ParsedRange> sorted =
                ranges.stream()
                        .sorted(
                                (a, b) ->
                                        KnownVulnerabilities.compareVersions(
                                                a.introduced(), b.introduced()))
                        .toList();
        for (int i = 1; i < sorted.size(); i++) {
            ParsedRange a = sorted.get(i - 1);
            ParsedRange b = sorted.get(i);
            if (KnownVulnerabilities.compareVersions(a.fixed(), b.introduced()) > 0) {
                throw new IllegalArgumentException(id + ": overlapping ranges " + a + " and " + b);
            }
        }
        ParsedRange lowest = sorted.get(0);
        if (!lowest.openLowerBound() && !isBranchStart(lowest.introduced())) {
            return sorted;
        }
        List<ParsedRange> result = new ArrayList<>(sorted);
        result.set(
                0,
                new ParsedRange(
                        "0", lowest.fixed(), true, lowest.fixedKnown(), lowest.openLowerBound()));
        return result;
    }

    /**
     * A brief plain text description taken from the markdown. The first real paragraph of the
     * "Summary" section is preferred, then of the "Impact" section, then of the whole text.
     * Headings, code blocks and very short paragraphs such as greetings are skipped, and the result
     * is truncated to a sensible length.
     *
     * @param markdown the advisory description
     * @return the description, empty if none could be found
     */
    static String firstParagraph(String markdown) {
        Map<String, List<String>> sections = sections(markdown);
        List<String> all = sections.values().stream().flatMap(List::stream).toList();
        String text =
                PREFERRED_SECTIONS.stream()
                        .map(sections::get)
                        .filter(java.util.Objects::nonNull)
                        .flatMap(List::stream)
                        .filter(p -> p.length() >= MIN_PARAGRAPH_LENGTH)
                        .findFirst()
                        .or(
                                () ->
                                        all.stream()
                                                .filter(p -> p.length() >= MIN_PARAGRAPH_LENGTH)
                                                .findFirst())
                        .or(() -> all.stream().findFirst())
                        .orElse("");
        if (text.length() <= MAX_DESCRIPTION_LENGTH) {
            return text;
        }
        int cut = text.lastIndexOf(' ', MAX_DESCRIPTION_LENGTH);
        return text.substring(0, cut > 0 ? cut : MAX_DESCRIPTION_LENGTH) + "...";
    }

    /**
     * Splits the markdown into sections keyed by lower case heading (empty before any heading),
     * each a list of plain text paragraphs.
     */
    private static Map<String, List<String>> sections(String markdown) {
        Map<String, List<String>> sections = new LinkedHashMap<>();
        String[] section = {""};
        boolean[] inCode = {false};
        StringBuilder paragraph = new StringBuilder();
        Runnable endParagraph =
                () -> {
                    if (!paragraph.toString().isBlank()) {
                        sections.computeIfAbsent(section[0], k -> new ArrayList<>())
                                .add(plainText(paragraph.toString()));
                    }
                    paragraph.setLength(0);
                };
        for (String raw : markdown.split("\\r?\\n")) {
            String line = raw.trim();
            if (line.startsWith("```")) {
                endParagraph.run();
                inCode[0] = !inCode[0];
            } else if (inCode[0]) {
                // Skip code
            } else if (line.startsWith("#")) {
                endParagraph.run();
                section[0] = line.replaceFirst("^#+", "").trim().toLowerCase(Locale.ROOT);
            } else if (line.isEmpty()) {
                endParagraph.run();
            } else {
                paragraph.append(line).append(' ');
            }
        }
        endParagraph.run();
        return sections;
    }

    private static String plainText(String markdown) {
        String text = MARKDOWN_LINK.matcher(markdown).replaceAll("$1");
        text = MARKDOWN_EMPHASIS.matcher(text).replaceAll("");
        return WHITESPACE.matcher(text).replaceAll(" ").trim();
    }
}
