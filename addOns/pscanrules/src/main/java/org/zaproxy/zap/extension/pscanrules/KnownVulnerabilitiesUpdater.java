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

import com.fasterxml.jackson.core.util.DefaultIndenter;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;
import com.fasterxml.jackson.core.util.Separators;
import com.fasterxml.jackson.core.util.Separators.Spacing;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.zaproxy.zap.extension.pscanrules.KnownVulnerabilities.Severity;
import org.zaproxy.zap.extension.pscanrules.KnownVulnerabilities.VersionRange;
import org.zaproxy.zap.extension.pscanrules.KnownVulnerabilities.Vulnerability;

/**
 * Regenerates a known vulnerabilities JSON file from published GitHub security advisories, and
 * fills in the help pages listing its entries. Run from the {@code updatePhpKnownVulnerabilities}
 * and {@code generatePhpKnownVulnerabilitiesHelp} Gradle tasks, not at scan time.
 *
 * <p>Entries with {@code "source": "manual"} in the existing file are preserved, as is its comment,
 * and the last updated date only changes when the vulnerabilities do. Set {@code GITHUB_TOKEN} to
 * authenticate the API calls.
 */
final class KnownVulnerabilitiesUpdater {

    static final String SOURCE_MANUAL = "manual";

    /**
     * The template of a vulnerability entry in the help pages, shared by all technologies and
     * rendered once per vulnerability.
     */
    static final String HELP_ENTRY_TEMPLATE_RESOURCE =
            "/org/zaproxy/zap/extension/pscanrules/resources/known-vulnerabilities-help-entry-template.html";

    /**
     * The tags in the source help pages which are replaced with the generated content, e.g. {@code
     * <wbr pscan-data="vulnerabilities" />}. Keeping the content out of the pages lets translators
     * change the surrounding text without touching it.
     */
    private static final Pattern HELP_TAG =
            Pattern.compile("<wbr\\s+pscan-data=[\"']([\\w-]+)[\"']\\s*/?>");

    static final String HELP_TAG_LAST_UPDATED = "lastUpdated";
    static final String HELP_TAG_COUNT = "count";
    static final String HELP_TAG_VULNERABILITIES = "vulnerabilities";

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Duration TIMEOUT = Duration.ofSeconds(60);
    private static final String GITHUB_TOKEN_ENV = "GITHUB_TOKEN";

    private KnownVulnerabilitiesUpdater() {}

    /**
     * Runs one of two commands: {@code update <json file>} regenerates the PHP known
     * vulnerabilities file from the advisories, and {@code help <json file> <page file name> <help
     * source dir> <help output dir>} fills in the vulnerabilities in each help page with that file
     * name under the source directory, writing the pages to the same relative paths under the
     * output directory, as done when the add-on is built.
     *
     * @param args the command and its arguments
     * @throws Exception if the advisories cannot be fetched or the files cannot be read or written
     */
    public static void main(String[] args) throws Exception {
        if (args.length == 2 && "update".equals(args[0])) {
            update(Paths.get(args[1]));
        } else if (args.length == 5 && "help".equals(args[0])) {
            generateHelp(Paths.get(args[1]), args[2], Paths.get(args[3]), Paths.get(args[4]));
        } else {
            System.err.println(
                    "Usage: KnownVulnerabilitiesUpdater update <json file> | help <json file> <page file name> <help source dir> <help output dir>");
            System.exit(1);
        }
    }

    private static void update(Path jsonFile) throws IOException, InterruptedException {
        List<JsonNode> advisories =
                fetchGitHubAdvisories(PhpAdvisories.API_URL, System.getenv(GITHUB_TOKEN_ENV));
        List<Vulnerability> generated =
                advisories.stream()
                        .map(PhpAdvisories::toVulnerability)
                        .flatMap(Optional::stream)
                        .toList();
        System.out.printf(
                "Fetched %d advisories, %d with a CVE.%n", advisories.size(), generated.size());

        KnownVulnerabilities existing =
                Files.exists(jsonFile)
                        ? KnownVulnerabilities.load(jsonFile)
                        : KnownVulnerabilities.EMPTY;
        KnownVulnerabilities updated = merge(existing, generated, LocalDate.now());
        Files.writeString(jsonFile, toJson(updated));
        System.out.printf(
                "Wrote %d vulnerabilities, last updated %s.%n",
                updated.vulnerabilities().size(), updated.lastUpdated());
    }

    private static void generateHelp(Path jsonFile, String pageName, Path sourceDir, Path outputDir)
            throws IOException {
        KnownVulnerabilities vulnerabilities = KnownVulnerabilities.load(jsonFile);
        String entryTemplate = readResource(HELP_ENTRY_TEMPLATE_RESOURCE);
        List<Path> pages;
        try (Stream<Path> files = Files.walk(sourceDir)) {
            pages =
                    files.filter(Files::isRegularFile)
                            .filter(file -> file.getFileName().toString().equals(pageName))
                            .toList();
        }
        if (pages.isEmpty()) {
            throw new IOException("No help page named " + pageName + " found under " + sourceDir);
        }
        for (Path page : pages) {
            Path output = outputDir.resolve(sourceDir.relativize(page));
            Files.createDirectories(output.getParent());
            Files.writeString(
                    output, toHelpHtml(Files.readString(page), entryTemplate, vulnerabilities));
            System.out.printf("Wrote %s%n", output);
        }
        System.out.printf(
                "Filled in %d vulnerabilities in %d help page(s).%n",
                vulnerabilities.vulnerabilities().size(), pages.size());
    }

    /**
     * Merges the generated vulnerabilities with the existing file: generated entries are sorted
     * newest first, the existing manual entries are appended unless now covered by a generated one,
     * and the last updated date is kept unless the vulnerabilities changed.
     *
     * @param existing the existing file, {@link KnownVulnerabilities#EMPTY} if none
     * @param generated the vulnerabilities generated from the advisories
     * @param today the date to use when the vulnerabilities changed
     * @return the merged file
     */
    static KnownVulnerabilities merge(
            KnownVulnerabilities existing, List<Vulnerability> generated, LocalDate today) {
        List<Vulnerability> sorted =
                generated.stream()
                        .sorted(
                                Comparator.comparing(
                                                Vulnerability::published,
                                                Comparator.nullsLast(Comparator.reverseOrder()))
                                        .thenComparing(Vulnerability::cve))
                        .toList();
        Set<String> cves = sorted.stream().map(Vulnerability::cve).collect(Collectors.toSet());
        List<Vulnerability> all = new ArrayList<>(sorted);
        existing.vulnerabilities().stream()
                .filter(v -> SOURCE_MANUAL.equals(v.source()) && !cves.contains(v.cve()))
                .forEach(all::add);

        boolean unchanged =
                all.equals(existing.vulnerabilities()) && existing.lastUpdated() != null;
        return new KnownVulnerabilities(
                existing.comment(),
                existing.schemaVersion() == null ? 1 : existing.schemaVersion(),
                unchanged ? existing.lastUpdated() : today.toString(),
                all);
    }

    /**
     * Serialises the vulnerabilities as pretty printed JSON, in the form the loader reads.
     *
     * @param vulnerabilities the vulnerabilities
     * @return the JSON, with a trailing newline
     * @throws IOException if the vulnerabilities cannot be serialised
     */
    static String toJson(KnownVulnerabilities vulnerabilities) throws IOException {
        DefaultIndenter indenter = new DefaultIndenter("  ", "\n");
        DefaultPrettyPrinter printer =
                new DefaultPrettyPrinter()
                        .withObjectIndenter(indenter)
                        .withArrayIndenter(indenter)
                        .withSeparators(
                                Separators.createDefaultInstance()
                                        .withObjectFieldValueSpacing(Spacing.AFTER));
        return MAPPER.writer(printer).writeValueAsString(vulnerabilities) + "\n";
    }

    /**
     * Fetches all the published advisories of a repository, following pagination.
     *
     * @param url the first page, e.g. {@link PhpAdvisories#API_URL}
     * @param token the GitHub token to authenticate with, may be {@code null}
     * @return the advisories
     * @throws IOException if a request fails or does not return 200
     * @throws InterruptedException if interrupted while waiting for a response
     */
    static List<JsonNode> fetchGitHubAdvisories(String url, String token)
            throws IOException, InterruptedException {
        HttpClient client = HttpClient.newBuilder().connectTimeout(TIMEOUT).build();
        List<JsonNode> all = new ArrayList<>();
        String next = url;
        while (next != null) {
            HttpRequest.Builder request =
                    HttpRequest.newBuilder(URI.create(next))
                            .timeout(TIMEOUT)
                            .header("Accept", "application/vnd.github+json")
                            .header("X-GitHub-Api-Version", "2022-11-28");
            if (token != null && !token.isBlank()) {
                request.header("Authorization", "Bearer " + token);
            }
            HttpResponse<String> response =
                    client.send(request.build(), BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() != 200) {
                throw new IOException(
                        "GitHub API returned "
                                + response.statusCode()
                                + " for "
                                + next
                                + ": "
                                + response.body());
            }
            MAPPER.readTree(response.body()).forEach(all::add);
            next = nextLink(response.headers().firstValue("Link").orElse(null));
        }
        return all;
    }

    /** The URL of the {@code rel="next"} link of a Link header, {@code null} if none. */
    static String nextLink(String header) {
        if (header == null) {
            return null;
        }
        return Stream.of(header.split(","))
                .map(String::trim)
                .filter(link -> link.endsWith("rel=\"next\""))
                .map(link -> link.substring(link.indexOf('<') + 1, link.indexOf('>')))
                .findFirst()
                .orElse(null);
    }

    /**
     * The id of the anchor for the CVE in the help page, lower case as the online help lower cases
     * ids.
     */
    static String anchor(String cve) {
        return cve.toLowerCase(Locale.ROOT);
    }

    /**
     * Fills in a help page, replacing its {@code <wbr pscan-data="..." />} tags: {@code
     * lastUpdated} and {@code count} with the corresponding values and {@code vulnerabilities} with
     * one entry per CVE, rendered from the entry template, most severe first then newest first.
     *
     * @param page the source help page
     * @param entryTemplate the template of a vulnerability entry
     * @param vulnerabilities the vulnerabilities
     * @return the HTML
     * @throws IllegalArgumentException if the page has a tag with an unknown name or no {@code
     *     vulnerabilities} tag
     */
    static String toHelpHtml(
            String page, String entryTemplate, KnownVulnerabilities vulnerabilities) {
        Map<String, String> values =
                Map.of(
                        HELP_TAG_LAST_UPDATED,
                        escape(Optional.ofNullable(vulnerabilities.lastUpdated()).orElse("")),
                        HELP_TAG_COUNT,
                        String.valueOf(vulnerabilities.vulnerabilities().size()),
                        HELP_TAG_VULNERABILITIES,
                        vulnerabilities.vulnerabilities().stream()
                                .sorted(
                                        Comparator.comparing(Vulnerability::getSeverity)
                                                .thenComparing(
                                                        Vulnerability::published,
                                                        Comparator.nullsLast(
                                                                Comparator.reverseOrder()))
                                                .thenComparing(Vulnerability::cve))
                                .map(v -> render(entryTemplate, entryValues(v)))
                                .collect(Collectors.joining()));

        boolean hasVulnerabilities = false;
        Matcher matcher = HELP_TAG.matcher(page);
        StringBuilder html = new StringBuilder();
        while (matcher.find()) {
            String name = matcher.group(1);
            String value = values.get(name);
            if (value == null) {
                throw new IllegalArgumentException("Unknown help page tag: " + matcher.group());
            }
            hasVulnerabilities |= HELP_TAG_VULNERABILITIES.equals(name);
            matcher.appendReplacement(html, Matcher.quoteReplacement(value));
        }
        if (!hasVulnerabilities) {
            throw new IllegalArgumentException(
                    "The help page has no <wbr pscan-data=\"vulnerabilities\" /> tag.");
        }
        return matcher.appendTail(html).toString();
    }

    static String readResource(String resource) throws IOException {
        try (InputStream in = KnownVulnerabilitiesUpdater.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IOException("Missing resource: " + resource);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    /** Replaces each {@code {{name}}} placeholder with its value. */
    static String render(String template, Map<String, String> values) {
        String result = template;
        for (Map.Entry<String, String> entry : values.entrySet()) {
            result = result.replace("{{" + entry.getKey() + "}}", entry.getValue());
        }
        return result;
    }

    private static Map<String, String> entryValues(Vulnerability v) {
        Severity severity = v.getSeverity();
        StringBuilder details = new StringBuilder();
        if (v.cvss() != null) {
            row(details, "CVSS score", v.cvss().toString());
        }
        if (v.component() != null) {
            row(details, "Component", v.component());
        }
        if (v.published() != null) {
            row(details, "Published", v.published());
        }
        if (v.ghsa() != null) {
            row(details, "GHSA", v.ghsa());
        }
        Map<String, String> values = new HashMap<>();
        values.put("anchor", anchor(v.cve()));
        values.put("cve", escape(v.cve()));
        values.put("severity", severity.name().charAt(0) + severity.getKey().substring(1));
        values.put("name", escape(Optional.ofNullable(v.name()).orElse("")));
        values.put(
                "description",
                v.description() == null || v.description().isBlank()
                        ? ""
                        : "<p>\n" + escape(v.description()) + "\n");
        values.put("details", details.toString());
        values.put(
                "affected",
                v.affected().stream()
                        .map(KnownVulnerabilitiesUpdater::rangeText)
                        .map(KnownVulnerabilitiesUpdater::escape)
                        .collect(Collectors.joining("<br>")));
        values.put(
                "references",
                Optional.ofNullable(v.links()).orElse(List.of()).stream()
                        .map(
                                link ->
                                        "<li><a href=\""
                                                + escape(link)
                                                + "\">"
                                                + escape(link)
                                                + "</a>\n")
                        .collect(Collectors.joining()));
        return values;
    }

    private static void row(StringBuilder html, String label, String value) {
        html.append("<tr><td>")
                .append(escape(label))
                .append(":</td><td>")
                .append(escape(value))
                .append("</td></tr>\n");
    }

    /** A readable form of an affected range, e.g. "8.1.0 and later, before 8.1.29". */
    static String rangeText(VersionRange range) {
        String text;
        if (range.fixed() == null) {
            text = range.introduced() + " and later, no fix available";
        } else if ("0".equals(range.introduced())) {
            text = "all versions before " + range.fixed();
        } else {
            text = range.introduced() + " and later, before " + range.fixed();
        }
        return range.assumed()
                ? text + " (assumed, older branches are not listed in the advisory)"
                : text;
    }

    private static String escape(String text) {
        return text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
    }
}
