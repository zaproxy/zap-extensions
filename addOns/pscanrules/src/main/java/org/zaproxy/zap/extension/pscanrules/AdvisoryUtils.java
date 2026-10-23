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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;
import org.zaproxy.zap.extension.pscanrules.KnownVulnerabilities.VersionRange;

/** Version range and text helpers shared by the advisory converters of the technologies. */
final class AdvisoryUtils {

    private static final int MAX_DESCRIPTION_LENGTH = 500;

    /** Paragraphs shorter than this are greetings or similar noise rather than a description. */
    private static final int MIN_PARAGRAPH_LENGTH = 30;

    private static final List<String> PREFERRED_SECTIONS = List.of("summary", "impact");
    private static final Pattern MARKDOWN_LINK = Pattern.compile("\\[([^]]*)]\\([^)]*\\)");
    private static final Pattern MARKDOWN_EMPHASIS = Pattern.compile("[`*]");
    private static final Pattern WHITESPACE = Pattern.compile("\\s+");

    /**
     * A range parsed from an advisory, {@code introduced <= version < fixed}.
     *
     * @param introduced the first affected version
     * @param fixed the first fixed version
     * @param assumed whether the advisory did not confirm the range, e.g. the lower bound was
     *     assumed or the versions were listed as only possibly affected
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

    private AdvisoryUtils() {}

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
     * The first version of the next branch, e.g. {@code 2.3.0} for {@code 2.2.34} or {@code 2.2}.
     */
    static String nextBranchStart(String version) {
        String[] parts = version.split("\\.");
        return parts[0] + "." + ((parts.length > 1 ? Long.parseLong(parts[1]) : 0) + 1) + ".0";
    }

    /**
     * Sorts the ranges of one advisory lowest first, failing on empty ranges and overlaps.
     *
     * @param ranges the ranges
     * @param id the advisory ID, for error messages
     * @return the sorted ranges
     * @throws IllegalArgumentException if a range is empty or two ranges overlap
     */
    static List<ParsedRange> sorted(List<ParsedRange> ranges, String id) {
        for (ParsedRange range : ranges) {
            if (range.fixed() != null
                    && KnownVulnerabilities.compareVersions(range.introduced(), range.fixed())
                            >= 0) {
                throw new IllegalArgumentException(id + ": empty range " + range);
            }
        }
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
        return sorted;
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
                        .filter(Objects::nonNull)
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
