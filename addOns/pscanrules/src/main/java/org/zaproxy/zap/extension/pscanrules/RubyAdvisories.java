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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;
import org.zaproxy.zap.extension.pscanrules.KnownVulnerabilities.Severity;
import org.zaproxy.zap.extension.pscanrules.KnownVulnerabilities.VersionRange;
import org.zaproxy.zap.extension.pscanrules.KnownVulnerabilities.Vulnerability;

/**
 * Converts the Ruby advisories of the <a href="https://github.com/rubysec/ruby-advisory-db">ruby
 * advisory database</a>, the files under {@code rubies/ruby}, into {@link Vulnerability
 * vulnerabilities}.
 *
 * <p>The advisories do not say which versions are affected, they list the versions which are not:
 * the {@code patched_versions} (fixed in each release line, e.g. {@code ~> 3.3.12}, and in all
 * later releases, e.g. {@code >= 4.0.3}) and sometimes the {@code unaffected_versions}. The
 * affected ranges are what is left when both are taken away. The versions below the lowest one
 * listed are not known to be affected, so such a range is assumed. The releases after the last one
 * listed are taken to be fixed, so that new releases are not reported.
 *
 * <p>The versions are cut down to three components as that is all the {@code Server} and {@code
 * X-Ruby-Version} headers give. Some old releases are listed with a patch level, e.g. {@code
 * 1.8.7.352} or {@code 1.8.5-p2}, which cannot be told from the header, so the release is taken to
 * be affected, as an assumed range.
 */
final class RubyAdvisories {

    static final String SOURCE_GENERATED = "ruby-advisory-db";
    static final String API_URL =
            "https://api.github.com/repos/rubysec/ruby-advisory-db/contents/rubies/ruby";
    static final String ADVISORY_FILE_SUFFIX = ".yml";

    private static final Pattern CVE = Pattern.compile("\\d{4}-\\d{4,}");
    private static final Pattern CONSTRAINT =
            Pattern.compile("^\\s*(~>|>=|>|<=|<)\\s*(\\d[\\w.+-]*)\\s*$");
    private static final Pattern VERSION = Pattern.compile("^(\\d{1,6}(?:\\.\\d{1,6})*)(.*)$");
    private static final Pattern PATCH_LEVEL = Pattern.compile("^[.-]?p(\\d+)$");
    private static final Pattern WHITESPACE = Pattern.compile("\\s+");

    private static final String LOWEST_VERSION = "0.0.0";
    private static final int MAX_LINKS = 6;

    private RubyAdvisories() {}

    /**
     * A range of releases {@code from <= version < to}, as listed by a version requirement.
     *
     * @param from the first version
     * @param to the first version after the range, {@code null} if there is no end
     * @param fromApproximate whether {@code from} is the release after one which has a patch level
     * @param toApproximate whether {@code to} is the release after one which has a patch level
     */
    private record Interval(
            String from, String to, boolean fromApproximate, boolean toApproximate) {

        boolean isEmpty() {
            return to != null && KnownVulnerabilities.compareVersions(from, to) >= 0;
        }
    }

    /**
     * Converts an advisory.
     *
     * @param advisory the advisory file, parsed
     * @return the vulnerability, empty if the advisory is not for a release of Ruby
     * @throws IllegalArgumentException if the advisory cannot be understood, so that changes to the
     *     format are noticed rather than silently dropped
     */
    static Optional<Vulnerability> toVulnerability(JsonNode advisory) {
        String number = advisory.path("cve").asText("");
        if (!CVE.matcher(number).matches()) {
            throw new IllegalArgumentException("Advisory without a valid CVE: " + advisory);
        }
        String cve = "CVE-" + number;
        if (!"ruby".equals(advisory.path("engine").asText("ruby"))) {
            return Optional.empty();
        }
        String title = WHITESPACE.matcher(advisory.path("title").asText("")).replaceAll(" ").trim();
        if (title.isEmpty()) {
            throw new IllegalArgumentException(cve + ": no title");
        }

        List<String> patched = strings(advisory.path("patched_versions"));
        List<String> unaffected = strings(advisory.path("unaffected_versions"));
        if (patched.isEmpty() && unaffected.isEmpty()) {
            throw new IllegalArgumentException(cve + ": no patched or unaffected versions");
        }
        List<VersionRange> ranges = affectedRanges(cve, patched, unaffected);

        Double cvss = cvss(advisory);
        Severity severity;
        if (cvss == null) {
            severity = Severity.MEDIUM;
            System.out.printf("WARNING: %s has no CVSS score, assuming medium severity.%n", cve);
        } else {
            severity = severity(cvss);
        }

        return Optional.of(
                new Vulnerability(
                        cve,
                        text(advisory, "ghsa"),
                        title,
                        AdvisoryUtils.firstParagraph(advisory.path("description").asText("")),
                        severity.getKey(),
                        cvss,
                        null,
                        ranges,
                        links(cve, advisory),
                        text(advisory, "date"),
                        SOURCE_GENERATED));
    }

    /** The affected ranges: everything which is not patched or unaffected. */
    private static List<VersionRange> affectedRanges(
            String cve, List<String> patched, List<String> unaffected) {
        List<Interval> unaffectedIntervals =
                Stream.concat(patched.stream(), unaffected.stream())
                        .map(c -> interval(cve, c))
                        .filter(i -> !i.isEmpty())
                        .sorted((a, b) -> KnownVulnerabilities.compareVersions(a.from(), b.from()))
                        .toList();

        List<VersionRange> affected = new ArrayList<>();
        String cursor = LOWEST_VERSION;
        // Nothing is known about the versions before the first one listed, unless it is one of
        // the unaffected ones starting at the lowest version.
        boolean cursorApproximate = true;
        for (Interval interval : unaffectedIntervals) {
            if (KnownVulnerabilities.compareVersions(interval.from(), cursor) > 0) {
                affected.add(
                        new VersionRange(
                                cursor,
                                interval.from(),
                                cursorApproximate || interval.fromApproximate()));
            }
            if (interval.to() == null) {
                // Everything from here on is patched.
                break;
            }
            if (KnownVulnerabilities.compareVersions(interval.to(), cursor) >= 0) {
                cursor = interval.to();
                cursorApproximate = interval.toApproximate();
            }
        }
        if (affected.isEmpty()) {
            throw new IllegalArgumentException(cve + ": no affected versions");
        }
        return affected;
    }

    /**
     * The releases matched by a version requirement, e.g. {@code ~> 3.3.12} is {@code 3.3.12} up to
     * {@code 3.4.0}.
     */
    private static Interval interval(String cve, String constraint) {
        Matcher c = CONSTRAINT.matcher(constraint);
        if (!c.matches()) {
            throw new IllegalArgumentException(cve + ": unexpected version " + constraint);
        }
        String operator = c.group(1);
        Matcher v = VERSION.matcher(c.group(2));
        if (!v.matches()) {
            throw new IllegalArgumentException(cve + ": unexpected version " + constraint);
        }
        String[] numbers = v.group(1).split("\\.");
        String rest = v.group(2);
        Matcher patchLevel = PATCH_LEVEL.matcher(rest);
        boolean isPatchLevel = patchLevel.matches();
        boolean hasPatchLevel =
                (isPatchLevel && Long.parseLong(patchLevel.group(1)) > 0)
                        || Stream.of(numbers).skip(3).anyMatch(n -> Long.parseLong(n) > 0);
        // A release candidate, e.g. 2.6.0-preview3, counts as the release.
        boolean preRelease = !rest.isEmpty() && !isPatchLevel;
        String base = threeComponents(numbers);
        // The version after all those with the patch level, e.g. 1.8.8 for 1.8.7.352.
        String afterPatchLevels = AdvisoryUtils.bumpPatch(base);
        String from = hasPatchLevel ? afterPatchLevels : base;

        switch (operator) {
            case "~>" -> {
                int segments = numbers.length + (isPatchLevel ? 1 : 0);
                String to;
                if (segments >= 4) {
                    to = afterPatchLevels;
                } else if (segments == 3) {
                    to = AdvisoryUtils.nextBranchStart(base);
                } else {
                    to = (Long.parseLong(numbers[0]) + 1) + ".0.0";
                }
                return new Interval(from, to, hasPatchLevel, hasPatchLevel);
            }
            case ">=" -> {
                return new Interval(from, null, hasPatchLevel, false);
            }
            case ">" -> {
                return new Interval(
                        preRelease || hasPatchLevel ? from : AdvisoryUtils.bumpPatch(base),
                        null,
                        hasPatchLevel,
                        false);
            }
            case "<" -> {
                return new Interval(LOWEST_VERSION, from, false, hasPatchLevel);
            }
            default -> {
                // <=
                return new Interval(
                        LOWEST_VERSION, AdvisoryUtils.bumpPatch(base), false, hasPatchLevel);
            }
        }
    }

    /** The first three numbers of the version, padded with zeros. */
    private static String threeComponents(String[] numbers) {
        String[] parts = {"0", "0", "0"};
        for (int i = 0; i < Math.min(3, numbers.length); i++) {
            parts[i] = String.valueOf(Long.parseLong(numbers[i]));
        }
        return String.join(".", parts);
    }

    private static Severity severity(double cvss) {
        if (cvss >= 9.0) {
            return Severity.CRITICAL;
        }
        if (cvss >= 7.0) {
            return Severity.HIGH;
        }
        if (cvss >= 4.0) {
            return Severity.MEDIUM;
        }
        return Severity.LOW;
    }

    /** The CVSS v3 score, else the v2 one, {@code null} if neither is given. */
    private static Double cvss(JsonNode advisory) {
        return Stream.of("cvss_v3", "cvss_v2")
                .map(advisory::path)
                .filter(JsonNode::isNumber)
                .map(JsonNode::asDouble)
                .findFirst()
                .orElse(null);
    }

    /** The advisory's own link and the first of its related links, without duplicates. */
    private static List<String> links(String cve, JsonNode advisory) {
        Set<String> links = new LinkedHashSet<>();
        links.add("https://nvd.nist.gov/vuln/detail/" + cve);
        String url = text(advisory, "url");
        if (url != null) {
            links.add(url);
        }
        strings(advisory.path("related").path("url")).stream()
                .filter(l -> l.startsWith("https://"))
                .forEach(links::add);
        return links.stream().limit(MAX_LINKS).toList();
    }

    private static String text(JsonNode node, String field) {
        String value = node.path(field).asText("");
        return value.isBlank() ? null : value.trim();
    }

    private static List<String> strings(JsonNode array) {
        return array.isArray()
                ? StreamSupport.stream(array.spliterator(), false).map(JsonNode::asText).toList()
                : List.of();
    }
}
