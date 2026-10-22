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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.core.scanner.Alert;

/**
 * The known vulnerabilities of a technology, as loaded from a known vulnerabilities JSON file such
 * as {@code php-known-vulnerabilities.json}, bundled with the add-on.
 *
 * @param comment the free text comment documenting the file, may be {@code null}
 * @param schemaVersion the version of the file format, may be {@code null}
 * @param lastUpdated the date the vulnerabilities were last updated, may be {@code null}
 * @param vulnerabilities the vulnerabilities
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(Include.NON_NULL)
@JsonPropertyOrder({"_comment", "schemaVersion", "lastUpdated", "vulnerabilities"})
record KnownVulnerabilities(
        @JsonProperty("_comment") List<String> comment,
        Integer schemaVersion,
        String lastUpdated,
        List<Vulnerability> vulnerabilities) {

    private static final Logger LOGGER = LogManager.getLogger(KnownVulnerabilities.class);

    static final KnownVulnerabilities EMPTY = new KnownVulnerabilities(null, null, null, List.of());

    /** Returns a copy with the given vulnerabilities. */
    KnownVulnerabilities withVulnerabilities(List<Vulnerability> vulnerabilities) {
        return new KnownVulnerabilities(comment, schemaVersion, lastUpdated, vulnerabilities);
    }

    /** Returns a copy with the given last updated date. */
    KnownVulnerabilities withLastUpdated(String lastUpdated) {
        return new KnownVulnerabilities(comment, schemaVersion, lastUpdated, vulnerabilities);
    }

    /**
     * A known vulnerability (a CVE) of the technology.
     *
     * @param cve the CVE ID
     * @param ghsa the GitHub Security Advisory ID, may be {@code null}
     * @param name a short title
     * @param description a brief description
     * @param severity one of {@code low}, {@code medium}, {@code high}, {@code critical}
     * @param cvss the CVSS base score, may be {@code null}
     * @param component the affected PHP component (e.g. {@code ext-soap}), {@code null} for PHP
     *     itself
     * @param affected the affected version ranges
     * @param links the references, the first being the primary one
     * @param published the publication date, may be {@code null}
     * @param source where the entry came from, e.g. {@code github-advisories} or {@code manual}
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonInclude(Include.NON_NULL)
    record Vulnerability(
            String cve,
            String ghsa,
            String name,
            String description,
            String severity,
            Double cvss,
            String component,
            List<VersionRange> affected,
            List<String> links,
            String published,
            String source) {

        boolean affects(String version) {
            return matchingRange(version).isPresent();
        }

        /** Returns the range which includes the given version, if any. */
        Optional<VersionRange> matchingRange(String version) {
            return affected == null
                    ? Optional.empty()
                    : affected.stream().filter(r -> r.contains(version)).findFirst();
        }

        /** The severity, {@link Severity#LOW} when missing or not recognised. */
        Severity getSeverity() {
            return Severity.of(severity);
        }

        /** The ZAP risk of the severity. */
        int getRisk() {
            return getSeverity().getRisk();
        }

        private boolean isValid() {
            return cve != null
                    && affected != null
                    && affected.stream().allMatch(VersionRange::isValid);
        }
    }

    /** The severities, most severe first, each mapped to a ZAP risk. */
    enum Severity {
        CRITICAL(Alert.RISK_HIGH),
        HIGH(Alert.RISK_HIGH),
        MEDIUM(Alert.RISK_MEDIUM),
        LOW(Alert.RISK_LOW);

        private final int risk;

        Severity(int risk) {
            this.risk = risk;
        }

        int getRisk() {
            return risk;
        }

        /** The lower case name, as used in the data file and the message keys. */
        String getKey() {
            return name().toLowerCase(Locale.ROOT);
        }

        /** Returns the severity for the given data file value, {@link #LOW} if not recognised. */
        static Severity of(String value) {
            if (value == null) {
                return LOW;
            }
            try {
                return valueOf(value.trim().toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException e) {
                return LOW;
            }
        }
    }

    /** Orders vulnerabilities by severity, most severe first, then by CVE ID. */
    static final Comparator<Vulnerability> MOST_SEVERE_FIRST =
            Comparator.comparing(Vulnerability::getSeverity).thenComparing(Vulnerability::cve);

    /**
     * A range of affected versions, {@code introduced <= version < fixed}. A {@code null} {@code
     * fixed} means every version from {@code introduced} onwards is affected.
     *
     * @param introduced the first affected version
     * @param fixed the first fixed version, may be {@code null}
     * @param assumed {@code true} when {@code introduced} was not stated by the advisory but
     *     assumed, i.e. older end-of-life branches are presumed affected
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    record VersionRange(
            String introduced, String fixed, @JsonInclude(Include.NON_DEFAULT) boolean assumed) {

        private boolean isValid() {
            return isVersion(introduced) && (fixed == null || isVersion(fixed));
        }

        boolean contains(String version) {
            return compareVersions(version, introduced) >= 0
                    && (fixed == null || compareVersions(version, fixed) < 0);
        }
    }

    /**
     * Loads the known vulnerabilities from the given class path resource. Returns {@link #EMPTY} if
     * the resource does not exist or cannot be parsed.
     *
     * @param resource the absolute name of the resource, e.g. {@code
     *     /org/zaproxy/zap/extension/pscanrules/resources/php-known-vulnerabilities.json}
     * @return the known vulnerabilities, never {@code null}
     */
    static KnownVulnerabilities loadResource(String resource) {
        try (InputStream in = KnownVulnerabilities.class.getResourceAsStream(resource)) {
            if (in == null) {
                LOGGER.warn("No such resource: {}", resource);
                return EMPTY;
            }
            return load(in, resource);
        } catch (IOException e) {
            LOGGER.warn("Failed to read known vulnerabilities resource {}", resource, e);
            return EMPTY;
        }
    }

    /**
     * Loads the known vulnerabilities from the given file. Returns {@link #EMPTY} if the file does
     * not exist or cannot be parsed.
     *
     * @param path the file to load
     * @return the known vulnerabilities, never {@code null}
     */
    static KnownVulnerabilities load(Path path) {
        if (!Files.exists(path)) {
            LOGGER.warn("No such file: {}", path.toAbsolutePath());
            return EMPTY;
        }
        try (InputStream in = Files.newInputStream(path)) {
            return load(in, path.toString());
        } catch (IOException e) {
            LOGGER.warn("Failed to read known vulnerabilities file {}", path, e);
            return EMPTY;
        }
    }

    private static KnownVulnerabilities load(InputStream in, String name) {
        try {
            KnownVulnerabilities all =
                    new ObjectMapper()
                            .enable(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY)
                            .readValue(in, KnownVulnerabilities.class);
            if (all.vulnerabilities() == null) {
                return EMPTY;
            }
            List<Vulnerability> valid =
                    all.vulnerabilities().stream().filter(Vulnerability::isValid).toList();
            if (valid.size() != all.vulnerabilities().size()) {
                all.vulnerabilities().stream()
                        .filter(v -> !v.isValid())
                        .forEach(
                                v ->
                                        LOGGER.warn(
                                                "Ignoring vulnerability {} in {}, it has an invalid version range.",
                                                v.cve(),
                                                name));
            }
            return all.withVulnerabilities(valid);
        } catch (IOException e) {
            LOGGER.warn(
                    "Failed to parse known vulnerabilities from {}: {}", name, e.getMessage(), e);
            return EMPTY;
        }
    }

    /** Returns the vulnerabilities which affect the given version, most severe first. */
    List<Vulnerability> getVulnerabilities(String version) {
        return vulnerabilities.stream()
                .filter(p -> p.affects(version))
                .sorted(MOST_SEVERE_FIRST)
                .toList();
    }

    /**
     * Compares two dotted numeric versions (e.g. {@code 8.1.29}), treating missing trailing
     * components as zero, so {@code 8.1} equals {@code 8.1.0}.
     */
    /** Matches a dotted numeric version with components which fit in a {@code long}. */
    private static final Pattern VERSION_PATTERN = Pattern.compile("\\d{1,18}(?:\\.\\d{1,18})*");

    static boolean isVersion(String version) {
        return version != null && VERSION_PATTERN.matcher(version).matches();
    }

    static int compareVersions(String a, String b) {
        String[] pa = a.split("\\.");
        String[] pb = b.split("\\.");
        for (int i = 0; i < Math.max(pa.length, pb.length); i++) {
            int cmp = Long.compare(component(pa, i), component(pb, i));
            if (cmp != 0) {
                return cmp;
            }
        }
        return 0;
    }

    private static long component(String[] parts, int i) {
        return i < parts.length ? Long.parseLong(parts[i]) : 0;
    }
}
