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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;
import org.zaproxy.zap.extension.pscanrules.AdvisoryUtils.ParsedRange;
import org.zaproxy.zap.extension.pscanrules.KnownVulnerabilities.Severity;
import org.zaproxy.zap.extension.pscanrules.KnownVulnerabilities.Vulnerability;

/**
 * Converts the CVE records published by the Apache HTTP Server project, one JSON file per CVE under
 * {@link #JSON_DIR_URL}, into {@link Vulnerability vulnerabilities}. The project does not publish
 * GitHub security advisories.
 *
 * <p>Two record formats are mixed: CVE JSON 5 ({@code containers.cna}) for the recent CVEs, where
 * the affected versions are mostly "branch X, less than or equal to Y", and CVE JSON 4 ({@code
 * CVE_data_meta}, {@code affects}) for the older ones, which list every affected release
 * individually, some only as possibly affected ({@code ?=}). Neither states the fixed version in
 * the version data; it is a timeline entry such as {@code "2.4.64 released"}. Branches without a
 * fix ("never released", end of life) are capped at the start of the next branch so that they
 * cannot match later branches.
 */
final class ApacheHttpdAdvisories {

    static final String SOURCE_GENERATED = "apache-httpd-json";
    static final String JSON_DIR_URL = "https://httpd.apache.org/security/json/";
    static final String SECURITY_URL = "https://httpd.apache.org/security/";

    private static final Pattern RECORD_LINK =
            Pattern.compile("href=\"(CVE-\\d{4}-\\d{4,}\\.json)\"");

    /**
     * A timeline entry naming a release, e.g. {@code 2.4.64 released} or {@code released in
     * 2.4.54}.
     */
    private static final Pattern RELEASED =
            Pattern.compile(
                    "^(?:released in\\s+(\\d+\\.\\d+\\.\\d+)|(\\d+\\.\\d+\\.\\d+)\\s+released?)$",
                    Pattern.CASE_INSENSITIVE);

    private static final Pattern NEVER_RELEASED =
            Pattern.compile("^(\\d+(?:\\.\\d+)*)-never released$", Pattern.CASE_INSENSITIVE);

    /** A version possibly followed by a qualifier, e.g. {@code 2.3.5-alpha}, which is dropped. */
    private static final Pattern VERSION = Pattern.compile("^(\\d+(?:\\.\\d+)*)(?:-\\w+)?$");

    private static final Pattern DATE = Pattern.compile("^\\d{4}-\\d{2}-\\d{2}");
    private static final Set<String> BRANCHES_WITH_PAGES = Set.of("1.3", "2.0", "2.2", "2.4");
    private static final Map<String, Severity> SEVERITIES =
            Map.of(
                    "low", Severity.LOW,
                    "moderate", Severity.MEDIUM,
                    "important", Severity.HIGH,
                    "critical", Severity.CRITICAL);

    /**
     * The severity of records for issues which are not vulnerabilities in the server itself, e.g.
     * the "httpoxy" mitigation for CGI applications (CVE-2016-5387); such records are skipped.
     */
    private static final String SEVERITY_NOT_APPLICABLE = "n/a";

    /** The versions of one release branch mentioned by a record. */
    private static final class Branch {
        private final Set<String> affected = new TreeSet<>(KnownVulnerabilities::compareVersions);
        private final Set<String> possiblyAffected =
                new TreeSet<>(KnownVulnerabilities::compareVersions);
        private String lower;
        private String upper;

        private String highest() {
            return Stream.concat(affected.stream(), possiblyAffected.stream())
                    .max(KnownVulnerabilities::compareVersions)
                    .orElse(null);
        }
    }

    private ApacheHttpdAdvisories() {}

    /**
     * The URLs of the CVE records linked from the directory listing of {@link #JSON_DIR_URL}.
     *
     * @param listing the HTML directory listing
     * @return the record URLs, sorted
     */
    static List<String> recordUrls(String listing) {
        return RECORD_LINK
                .matcher(listing)
                .results()
                .map(r -> JSON_DIR_URL + r.group(1))
                .distinct()
                .sorted()
                .toList();
    }

    /**
     * Converts one record, returning empty when it should be skipped: rejected, without a CVE, or
     * with a severity of "n/a", which the project uses for issues which are not vulnerabilities in
     * the server itself.
     *
     * @param record the CVE record, in CVE JSON 4 or 5 format
     * @return the vulnerability, or empty
     * @throws IllegalArgumentException if the record cannot be understood, so that new formats are
     *     noticed rather than silently dropped
     */
    static Optional<Vulnerability> toVulnerability(JsonNode record) {
        return record.has("containers") ? fromCve5(record) : fromCve4(record);
    }

    private static Optional<Vulnerability> fromCve5(JsonNode record) {
        JsonNode meta = record.path("cveMetadata");
        String cve = text(meta, "cveId");
        if (cve == null || "REJECTED".equals(text(meta, "state"))) {
            return Optional.empty();
        }
        JsonNode cna = record.path("containers").path("cna");
        List<JsonNode> timeline = list(cna.path("timeline"));

        Map<String, Branch> branches = new LinkedHashMap<>();
        List<ParsedRange> ranges = new ArrayList<>();
        for (JsonNode affected : list(cna.path("affected"))) {
            for (JsonNode version : list(affected.path("versions"))) {
                if (!"affected".equals(text(version, "status"))) {
                    continue;
                }
                String from = version(text(version, "version"), cve);
                String lessThan = text(version, "lessThan");
                String lessThanOrEqual = text(version, "lessThanOrEqual");
                if (lessThan != null) {
                    ranges.add(new ParsedRange(lowerBound(from), version(lessThan, cve), false));
                } else if (lessThanOrEqual != null) {
                    Branch branch = branch(branches, lessThanOrEqual);
                    if (branch.upper != null) {
                        throw new IllegalArgumentException(
                                cve + ": two upper bounds for branch " + branchOf(lessThanOrEqual));
                    }
                    branch.lower = lowerBound(from);
                    branch.upper = version(lessThanOrEqual, cve);
                } else {
                    branch(branches, from).affected.add(from);
                }
            }
        }
        ranges.addAll(toRanges(branches, timeline, cve));

        String severity =
                list(cna.path("metrics")).stream()
                        .map(m -> text(m.path("other").path("content"), "text"))
                        .filter(s -> s != null)
                        .findFirst()
                        .orElse(null);
        String description =
                list(cna.path("descriptions")).stream()
                        .filter(
                                d ->
                                        Optional.ofNullable(text(d, "lang"))
                                                .orElse("")
                                                .startsWith("en"))
                        .findFirst()
                        .or(() -> list(cna.path("descriptions")).stream().findFirst())
                        .map(d -> text(d, "value"))
                        .orElse("");
        return vulnerability(
                cve,
                text(cna, "title"),
                description,
                severity,
                ranges,
                date(text(meta, "datePublished"), timeline));
    }

    private static Optional<Vulnerability> fromCve4(JsonNode record) {
        JsonNode meta = record.path("CVE_data_meta");
        String cve = text(meta, "ID");
        if (cve == null || "REJECT".equals(text(meta, "STATE"))) {
            return Optional.empty();
        }
        List<JsonNode> timeline = list(record.path("timeline"));

        Map<String, Branch> branches = new LinkedHashMap<>();
        for (JsonNode vendor : list(record.path("affects").path("vendor").path("vendor_data"))) {
            for (JsonNode product : list(vendor.path("product").path("product_data"))) {
                for (JsonNode version : list(product.path("version").path("version_data"))) {
                    String value = version(text(version, "version_value"), cve);
                    Branch branch = branch(branches, value);
                    String operator =
                            Optional.ofNullable(text(version, "version_affected")).orElse("=");
                    switch (operator) {
                        case "=" -> branch.affected.add(value);
                        case "?=" -> branch.possiblyAffected.add(value);
                        case "<=" -> branch.upper = value;
                        case "<" -> branch.upper = previousPatch(value, cve);
                        case ">=", "!<" -> branch.lower = value;
                        default ->
                                throw new IllegalArgumentException(
                                        cve + ": unknown version_affected '" + operator + "'");
                    }
                }
            }
        }

        String severity =
                list(record.path("impact")).stream()
                        .map(i -> text(i, "other"))
                        .filter(s -> s != null)
                        .findFirst()
                        .orElse(null);
        String description =
                list(record.path("description").path("description_data")).stream()
                        .map(d -> text(d, "value"))
                        .filter(d -> d != null)
                        .findFirst()
                        .orElse("");
        return vulnerability(
                cve,
                text(meta, "TITLE"),
                description,
                severity,
                toRanges(branches, timeline, cve),
                date(text(meta, "DATE_PUBLIC"), timeline));
    }

    /**
     * Builds the vulnerability, empty for records whose severity is not applicable, which the
     * project uses for issues which are not vulnerabilities in the server itself.
     */
    private static Optional<Vulnerability> vulnerability(
            String cve,
            String title,
            String description,
            String severity,
            List<ParsedRange> ranges,
            String published) {
        String severityKey = Optional.ofNullable(severity).orElse("").toLowerCase(Locale.ROOT);
        if (SEVERITY_NOT_APPLICABLE.equals(severityKey)) {
            System.out.printf("Skipping %s, its severity is not applicable: %s%n", cve, title);
            return Optional.empty();
        }
        if (ranges.isEmpty()) {
            throw new IllegalArgumentException(cve + ": no affected versions");
        }
        Severity mapped = SEVERITIES.get(severityKey);
        if (mapped == null) {
            throw new IllegalArgumentException(cve + ": unknown severity '" + severity + "'");
        }
        List<ParsedRange> affected = AdvisoryUtils.sorted(ranges, cve);

        String page =
                affected.stream()
                        .map(r -> branchOf(r.fixed()))
                        .filter(BRANCHES_WITH_PAGES::contains)
                        .max(KnownVulnerabilities::compareVersions)
                        .orElse("2.4");
        List<String> links =
                List.of(
                        SECURITY_URL + "vulnerabilities_" + page.replace(".", "") + ".html#" + cve,
                        "https://nvd.nist.gov/vuln/detail/" + cve,
                        JSON_DIR_URL + cve + ".json");

        return Optional.of(
                new Vulnerability(
                        cve,
                        null,
                        Optional.ofNullable(title).orElse("").trim(),
                        AdvisoryUtils.firstParagraph(Optional.ofNullable(description).orElse("")),
                        mapped.getKey(),
                        null,
                        null,
                        affected.stream().map(ParsedRange::toVersionRange).toList(),
                        links,
                        published,
                        SOURCE_GENERATED));
    }

    /**
     * One or two ranges per branch: the fixed version is the release of that branch in the
     * timeline, else the start of the next branch when the timeline says the branch never got a
     * release, else the version after the stated or highest affected one. Possibly affected
     * versions below the confirmed ones form their own, assumed, range.
     */
    private static List<ParsedRange> toRanges(
            Map<String, Branch> branches, List<JsonNode> timeline, String cve) {
        List<String> released = new ArrayList<>();
        Set<String> neverReleased = new TreeSet<>();
        for (JsonNode entry : timeline) {
            String value = value(entry);
            Matcher m = RELEASED.matcher(value);
            if (m.matches()) {
                released.add(m.group(1) != null ? m.group(1) : m.group(2));
            }
            m = NEVER_RELEASED.matcher(value);
            if (m.matches()) {
                neverReleased.add(branchOf(m.group(1)));
            }
        }

        List<ParsedRange> ranges = new ArrayList<>();
        branches.forEach(
                (name, branch) -> {
                    // The release which fixed the branch must be newer than the affected versions;
                    // a few records list the fixing release as affected too.
                    String highest =
                            Stream.of(branch.upper, branch.highest())
                                    .filter(v -> v != null)
                                    .max(KnownVulnerabilities::compareVersions)
                                    .orElse("0");
                    String fixed =
                            released.stream()
                                    .filter(v -> branchOf(v).equals(name))
                                    .filter(
                                            v ->
                                                    KnownVulnerabilities.compareVersions(v, highest)
                                                            > 0)
                                    .min(KnownVulnerabilities::compareVersions)
                                    .orElse(null);
                    boolean fixedKnown = fixed != null;
                    if (fixed == null && neverReleased.contains(name)) {
                        fixed = AdvisoryUtils.nextBranchStart(name);
                    } else if (fixed == null && branch.upper != null) {
                        fixed = AdvisoryUtils.bumpPatch(branch.upper);
                    } else if (fixed == null && branch.highest() != null) {
                        fixed = AdvisoryUtils.bumpPatch(branch.highest());
                    } else if (fixed == null) {
                        throw new IllegalArgumentException(
                                cve + ": no upper bound for branch " + name);
                    }

                    String introduced =
                            branch.lower != null
                                    ? branch.lower
                                    : branch.affected.stream().findFirst().orElse(null);
                    String possibly = branch.possiblyAffected.stream().findFirst().orElse(null);
                    if (introduced == null && possibly == null) {
                        // Only an upper bound was given, so the whole branch up to it is affected.
                        introduced = AdvisoryUtils.branchStart(name);
                    }
                    if (introduced == null) {
                        ranges.add(new ParsedRange(possibly, fixed, true, fixedKnown, false));
                    } else if (possibly != null
                            && KnownVulnerabilities.compareVersions(
                                            branch.possiblyAffected.stream()
                                                    .reduce((a, b) -> b)
                                                    .orElseThrow(),
                                            introduced)
                                    < 0) {
                        ranges.add(new ParsedRange(possibly, introduced, true, fixedKnown, false));
                        ranges.add(new ParsedRange(introduced, fixed, false, fixedKnown, false));
                    } else {
                        ranges.add(
                                new ParsedRange(
                                        possibly != null
                                                        && KnownVulnerabilities.compareVersions(
                                                                        possibly, introduced)
                                                                < 0
                                                ? possibly
                                                : introduced,
                                        fixed,
                                        false,
                                        fixedKnown,
                                        false));
                    }
                });
        return ranges;
    }

    /**
     * The lower bound of a range starting at a version or branch, {@code 0} meaning all versions.
     */
    private static String lowerBound(String from) {
        return "0".equals(from) ? "0" : AdvisoryUtils.branchStart(from);
    }

    private static Branch branch(Map<String, Branch> branches, String version) {
        return branches.computeIfAbsent(branchOf(version), k -> new Branch());
    }

    /** The branch of a version, e.g. {@code 2.4} for {@code 2.4.63}. */
    static String branchOf(String version) {
        String[] parts = version.split("\\.");
        return parts[0] + "." + (parts.length > 1 ? parts[1] : "0");
    }

    private static String previousPatch(String version, String cve) {
        String[] parts = version.split("\\.");
        long patch = parts.length > 2 ? Long.parseLong(parts[2]) : 0;
        if (patch == 0) {
            throw new IllegalArgumentException(cve + ": cannot step back from " + version);
        }
        return parts[0] + "." + parts[1] + "." + (patch - 1);
    }

    private static String version(String text, String cve) {
        Matcher m = VERSION.matcher(Optional.ofNullable(text).orElse("").trim());
        if (!m.matches()) {
            throw new IllegalArgumentException(cve + ": not a version '" + text + "'");
        }
        return m.group(1);
    }

    /**
     * The date part of the stated publication date, else of the time of the "public" timeline
     * entry, else of the earliest release in the timeline, else of the earliest timeline entry,
     * else empty.
     */
    private static String date(String stated, List<JsonNode> timeline) {
        List<String> candidates = new ArrayList<>();
        candidates.add(stated);
        timelineTimes(timeline, "public").forEach(candidates::add);
        timelineTimes(timeline, RELEASED).sorted().forEach(candidates::add);
        timeline.stream().map(e -> text(e, "time")).sorted().forEach(candidates::add);
        return candidates.stream()
                .filter(d -> d != null)
                .map(DATE::matcher)
                .filter(Matcher::find)
                .map(Matcher::group)
                .findFirst()
                .orElse("");
    }

    private static Stream<String> timelineTimes(List<JsonNode> timeline, String value) {
        return timeline.stream()
                .filter(e -> value.equalsIgnoreCase(value(e)))
                .map(e -> text(e, "time"));
    }

    private static Stream<String> timelineTimes(List<JsonNode> timeline, Pattern value) {
        return timeline.stream()
                .filter(e -> value.matcher(value(e)).matches())
                .map(e -> text(e, "time"));
    }

    private static String value(JsonNode timelineEntry) {
        return Optional.ofNullable(text(timelineEntry, "value")).orElse("").trim();
    }

    private static List<JsonNode> list(JsonNode node) {
        return node.isArray()
                ? StreamSupport.stream(node.spliterator(), false).collect(Collectors.toList())
                : List.of();
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.path(field);
        return value.isTextual() && !value.asText().isBlank() ? value.asText() : null;
    }
}
