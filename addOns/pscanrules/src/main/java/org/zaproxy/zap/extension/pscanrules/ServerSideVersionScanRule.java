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

import java.nio.file.Path;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import net.htmlparser.jericho.Source;
import org.apache.commons.httpclient.URIException;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.extension.pscan.PassiveScanData;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.extension.pscanrules.KnownVulnerabilities.Severity;
import org.zaproxy.zap.extension.pscanrules.KnownVulnerabilities.VersionRange;
import org.zaproxy.zap.extension.pscanrules.KnownVulnerabilities.Vulnerability;
import org.zaproxy.zap.model.SessionStructure;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

/**
 * A passive scan rule which detects the versions of server side technologies disclosed in HTTP
 * response headers, e.g. {@code X-Powered-By: PHP/8.2.12} or {@code Server: Apache/2.4.41 (Ubuntu)
 * PHP/7.4.3}, and raises an alert when the version has known vulnerabilities (CVEs).
 *
 * <p>Each {@link Technology} has its own alert type, which is only raised when the technology is
 * enabled in the context of the message. Only the version of the technology itself is considered,
 * not the versions of its extensions or plugins. One alert is raised per site, technology and
 * disclosed version, with the risk of the most severe vulnerability, a description listing all of
 * the vulnerabilities which apply, and references linking to the help section of each.
 */
public class ServerSideVersionScanRule extends PluginPassiveScanner
        implements CommonPassiveScanRuleInfo {

    private static final String MESSAGE_PREFIX = "pscanrules.serversideversion.";
    private static final int PLUGIN_ID = 20020;

    static final String PHP_KNOWN_VULNERABILITIES_RESOURCE =
            "/org/zaproxy/zap/extension/pscanrules/resources/php-known-vulnerabilities.json";

    /** The online help page which details every known PHP vulnerability, with an anchor per CVE. */
    static final String PHP_HELP_URL =
            "https://www.zaproxy.org/docs/desktop/addons/passive-scan-rules/php-known-vulnerabilities/";

    static final String APACHE_KNOWN_VULNERABILITIES_RESOURCE =
            "/org/zaproxy/zap/extension/pscanrules/resources/apache-known-vulnerabilities.json";

    static final String APACHE_HELP_URL =
            "https://www.zaproxy.org/docs/desktop/addons/passive-scan-rules/apache-known-vulnerabilities/";

    /**
     * A parenthesised comment right after a version, e.g. {@code (Ubuntu)} in {@code Apache/2.4.58
     * (Ubuntu)}, bounded as the header values are attacker controlled.
     */
    private static final Pattern VERSION_COMMENT = Pattern.compile("^\\s*\\(([^()]{1,60})\\)");

    /** A parenthesised comment anywhere in a header value, which applies to all its tokens. */
    private static final Pattern HEADER_COMMENT = Pattern.compile("\\(([^()]{1,60})\\)");

    /**
     * A distribution package suffix right after a version, e.g. {@code -4ubuntu2.19} in {@code
     * PHP/7.4.3-4ubuntu2.19} or {@code -0+deb7u14}, bounded as the header values are attacker
     * controlled.
     */
    private static final Pattern VERSION_SUFFIX = Pattern.compile("^-[\\w.+~]{1,40}");

    private static final Pattern DISTRIBUTION_SUFFIX =
            Pattern.compile("ubuntu|deb|el\\d|fc\\d|mga|suse|alpine", Pattern.CASE_INSENSITIVE);

    /**
     * Names of distributions which package the technologies, and backport security fixes without
     * changing the version, so a version followed by one of them is likely to be patched already.
     */
    private static final Pattern DISTRIBUTION =
            Pattern.compile(
                    "\\b(?:Debian|Ubuntu|Raspbian|Red ?Hat|RHEL|CentOS|Fedora|Rocky|Alma(?:Linux)?|Oracle|SUSE|openSUSE|SLES|Amazon|Gentoo|Mageia|Mint|FreeBSD|OpenBSD|NetBSD)\\b",
                    Pattern.CASE_INSENSITIVE);

    /** The server side technologies detected, each with its own alert type. */
    public enum Technology {
        /**
         * PHP. Matches a {@code PHP/<version>} token. The lookbehind ensures the token is not the
         * tail of another product name (e.g. {@code mod_php/7.4} or {@code Some-PHP/1.0}), and only
         * the numeric part of the version is captured, so distro suffixes such as {@code
         * 7.4.3-4ubuntu2.19} are ignored. The digits per component are bounded as the header values
         * are attacker controlled.
         */
        PHP(
                1,
                2,
                "php",
                Tech.PHP,
                Pattern.compile(
                        "(?<![\\w-])PHP/(\\d{1,6}(?:\\.\\d{1,6}){0,2})", Pattern.CASE_INSENSITIVE),
                PHP_KNOWN_VULNERABILITIES_RESOURCE,
                PHP_HELP_URL),
        /**
         * Apache HTTP Server. Matches an {@code Apache/<version>} token, as sent in the {@code
         * Server} header unless {@code ServerTokens} is lowered. {@code Apache} alone, {@code
         * Apache-Coyote/1.1} (Tomcat) and module tokens such as {@code mod_apache/1.0} do not
         * match.
         */
        APACHE(
                3,
                4,
                "apache",
                Tech.Apache,
                Pattern.compile(
                        "(?<![\\w-])Apache/(\\d{1,6}(?:\\.\\d{1,6}){0,2})",
                        Pattern.CASE_INSENSITIVE),
                APACHE_KNOWN_VULNERABILITIES_RESOURCE,
                APACHE_HELP_URL);

        private final int alertRef;
        private final int incompleteAlertRef;
        private final String messageKey;
        private final Tech tech;
        private final Pattern versionPattern;
        private final String knownVulnerabilitiesResource;
        private final String helpUrl;

        Technology(
                int alertRef,
                int incompleteAlertRef,
                String messageKey,
                Tech tech,
                Pattern versionPattern,
                String knownVulnerabilitiesResource,
                String helpUrl) {
            this.alertRef = alertRef;
            this.incompleteAlertRef = incompleteAlertRef;
            this.messageKey = messageKey;
            this.tech = tech;
            this.versionPattern = versionPattern;
            this.knownVulnerabilitiesResource = knownVulnerabilitiesResource;
            this.helpUrl = helpUrl;
        }

        /** The ZAP technology, the alert type is only raised when it is enabled in the context. */
        public Tech getTech() {
            return tech;
        }

        /**
         * The alert reference of this technology's alert type for a complete version, e.g. {@code
         * 20020-1}.
         */
        public String getAlertRef() {
            return PLUGIN_ID + "-" + alertRef;
        }

        /**
         * The alert reference of this technology's alert type for an incomplete version, e.g.
         * {@code 20020-2}, raised at low risk and confidence as the version does not say whether
         * the vulnerabilities have been fixed.
         */
        public String getIncompleteAlertRef() {
            return PLUGIN_ID + "-" + incompleteAlertRef;
        }

        /** The display name of the technology, e.g. {@code PHP}. */
        public String getDisplayName() {
            return Constant.messages.getString(MESSAGE_PREFIX + messageKey + ".tech");
        }

        /** The name of this technology's alert type for a complete version. */
        public String getAlertName() {
            return Constant.messages.getString(MESSAGE_PREFIX + messageKey + ".name");
        }

        /** The name of this technology's alert type for an incomplete version. */
        public String getIncompleteAlertName() {
            return Constant.messages.getString(MESSAGE_PREFIX + messageKey + ".name.incomplete");
        }

        String getSolution() {
            return Constant.messages.getString(MESSAGE_PREFIX + messageKey + ".soln");
        }

        String getReference() {
            return Constant.messages.getString(MESSAGE_PREFIX + messageKey + ".refs");
        }

        /** The note explaining what an assumed version range means for this technology. */
        String getAssumedNote() {
            return Constant.messages.getString(MESSAGE_PREFIX + messageKey + ".otherinfo.assumed");
        }

        /** Loads the known vulnerabilities of this technology, bundled with the add-on. */
        KnownVulnerabilities loadKnownVulnerabilities() {
            return KnownVulnerabilities.loadResource(knownVulnerabilitiesResource);
        }

        /**
         * Returns the link to the section of the online help page which details the given problem.
         *
         * @param vulnerability the vulnerability
         * @return the link
         */
        String getHelpLink(Vulnerability vulnerability) {
            return helpUrl + "#" + vulnerability.cve().toLowerCase(Locale.ROOT);
        }
    }

    /** The tags common to all the alerts, the CVE tags being added per alert. */
    private static final Map<String, String> STATIC_ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2025_A03_SUPPLY_CHAIN,
                                CommonAlertTag.OWASP_2021_A06_VULN_COMP,
                                CommonAlertTag.OWASP_2017_A09_VULN_COMP,
                                CommonAlertTag.WSTG_V42_INFO_08_FINGERPRINT_APP_FRAMEWORK));
        alertTags.put(PolicyTag.API.getTag(), "");
        alertTags.put(PolicyTag.PENTEST.getTag(), "");
        alertTags.put(PolicyTag.QA_CICD.getTag(), "");
        alertTags.put(PolicyTag.QA_FULL.getTag(), "");
        alertTags.put(PolicyTag.QA_STD.getTag(), "");
        STATIC_ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    /** All the tags, i.e. the static ones plus a CVE tag for every known vulnerability. */
    private static volatile Map<String, String> allAlertTags;

    /**
     * The site, technology and version combinations already alerted on, shared by all instances as
     * the passive scanner copies the rule for every message. Cleared when the session changes.
     */
    private static final Set<String> ALERTED = ConcurrentHashMap.newKeySet();

    /**
     * The known vulnerabilities of each technology, loaded once and shared by all instances as the
     * passive scanner copies the rule for every message.
     */
    private static final Map<Technology, KnownVulnerabilities> KNOWN_VULNERABILITIES =
            new ConcurrentHashMap<>();

    /**
     * A technology version found in a response header.
     *
     * @param technology the technology
     * @param headerName the name of the header
     * @param version the numeric version, e.g. {@code 8.1.2}
     * @param evidence the matched text, e.g. {@code PHP/8.1.2}
     * @param distribution the distribution named right after the version, e.g. {@code Ubuntu} for
     *     {@code Apache/2.4.58 (Ubuntu)}, {@code null} if none
     */
    public record DetectedVersion(
            Technology technology,
            String headerName,
            String version,
            String evidence,
            String distribution) {

        public DetectedVersion(
                Technology technology, String headerName, String version, String evidence) {
            this(technology, headerName, version, evidence, null);
        }

        /**
         * Whether the version has all three components, e.g. {@code 8.1.2} rather than {@code 8.1}.
         */
        boolean isComplete() {
            return KnownVulnerabilities.isCompleteVersion(version);
        }
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        List<DetectedVersion> versions = getVersions(msg.getResponseHeader());
        if (versions.isEmpty()) {
            return;
        }
        String site = getSite(msg);
        for (DetectedVersion version : versions) {
            if (!isEnabled(version.technology())) {
                continue;
            }
            String key = site + "|" + version.technology() + "|" + version.version();
            if (ALERTED.contains(key)) {
                continue;
            }
            List<Vulnerability> vulnerabilities =
                    getKnownVulnerabilities(version.technology(), version.version());
            if (!vulnerabilities.isEmpty() && ALERTED.add(key)) {
                buildAlert(version, vulnerabilities).raise();
            }
        }
    }

    /**
     * Whether the technology is enabled in the context of the message, all are when no context
     * matches.
     */
    private boolean isEnabled(Technology technology) {
        PassiveScanData helper = getHelper();
        TechSet techSet = helper == null ? null : helper.getTechSet();
        return techSet == null || techSet.includes(technology.getTech());
    }

    /** The site of the message, as named in the Sites tree, e.g. {@code https://example.com}. */
    private static String getSite(HttpMessage msg) {
        try {
            return SessionStructure.getHostName(msg);
        } catch (URIException e) {
            return msg.getRequestHeader().getURI().getEscapedAuthority();
        }
    }

    private AlertBuilder buildAlert(DetectedVersion version, List<Vulnerability> vulnerabilities) {
        Technology tech = version.technology();
        Vulnerability mostSevere = vulnerabilities.get(0);
        boolean assumedOnly =
                vulnerabilities.stream()
                        .allMatch(
                                v ->
                                        v.matchingRange(version.version())
                                                .map(VersionRange::assumed)
                                                .orElse(false));
        // An incomplete version, e.g. 2.4, matches every vulnerability of any 2.4.x release, but
        // does not say which of them the server has fixed, so it gets its own low risk alert type.
        boolean incomplete = !version.isComplete();
        return newAlert()
                .setName(incomplete ? tech.getIncompleteAlertName() : tech.getAlertName())
                .setAlertRef(incomplete ? tech.getIncompleteAlertRef() : tech.getAlertRef())
                .setRisk(incomplete ? Alert.RISK_LOW : mostSevere.getRisk())
                .setConfidence(
                        incomplete || assumedOnly || version.distribution() != null
                                ? Alert.CONFIDENCE_LOW
                                : Alert.CONFIDENCE_MEDIUM)
                .setDescription(
                        Constant.messages.getString(
                                MESSAGE_PREFIX + (incomplete ? "desc.incomplete" : "desc")))
                .setOtherInfo(getOtherInfo(version, vulnerabilities, assumedOnly))
                .setSolution(tech.getSolution())
                .setReference(getReferences(tech, vulnerabilities))
                .setTags(getAlertTags(vulnerabilities))
                .setEvidence(version.evidence())
                .setCweId(1395) // CWE-1395: Dependency on Vulnerable Third-Party Component
                .setWascId(13); // WASC-13: Information Leakage
    }

    /** The static tags plus a CVE tag for each of the given vulnerabilities. */
    private static Map<String, String> getAlertTags(List<Vulnerability> vulnerabilities) {
        Map<String, String> tags = new HashMap<>(STATIC_ALERT_TAGS);
        vulnerabilities.forEach(v -> CommonAlertTag.putCve(tags, v.cve()));
        return tags;
    }

    /**
     * The technology's static references followed by the link to the help section of each
     * vulnerability, most severe first.
     */
    private static String getReferences(Technology tech, List<Vulnerability> vulnerabilities) {
        return Stream.concat(
                        Stream.of(tech.getReference()),
                        vulnerabilities.stream().map(tech::getHelpLink))
                .collect(Collectors.joining("\n"));
    }

    /**
     * The other info: the disclosed version and header, the counts per severity, a note when the
     * version is only assumed to be affected, then the CVEs listed per severity, most severe first,
     * each separated by a blank line.
     */
    private static String getOtherInfo(
            DetectedVersion version, List<Vulnerability> vulnerabilities, boolean assumedOnly) {
        Map<Severity, List<String>> cvesBySeverity =
                vulnerabilities.stream()
                        .collect(
                                Collectors.groupingBy(
                                        Vulnerability::getSeverity,
                                        () -> new EnumMap<>(Severity.class),
                                        Collectors.mapping(
                                                Vulnerability::cve, Collectors.toList())));
        StringBuilder otherInfo =
                new StringBuilder(
                        Constant.messages.getString(
                                MESSAGE_PREFIX + "otherinfo.disclosed",
                                version.technology().getDisplayName(),
                                version.version(),
                                version.headerName()));
        if (version.distribution() != null) {
            otherInfo
                    .append("\n\n")
                    .append(
                            Constant.messages.getString(
                                    MESSAGE_PREFIX + "otherinfo.distribution",
                                    version.distribution()));
        }
        otherInfo
                .append("\n\n")
                .append(
                        Constant.messages.getString(
                                MESSAGE_PREFIX + "otherinfo.counts",
                                vulnerabilities.size(),
                                count(cvesBySeverity, Severity.CRITICAL),
                                count(cvesBySeverity, Severity.HIGH),
                                count(cvesBySeverity, Severity.MEDIUM),
                                count(cvesBySeverity, Severity.LOW)));
        if (assumedOnly) {
            otherInfo.append("\n\n").append(version.technology().getAssumedNote());
        }
        cvesBySeverity.forEach(
                (severity, cves) ->
                        otherInfo
                                .append("\n\n")
                                .append(
                                        Constant.messages.getString(
                                                MESSAGE_PREFIX
                                                        + "otherinfo.severity."
                                                        + severity.getKey(),
                                                String.join(", ", cves))));
        return otherInfo.toString();
    }

    private static int count(Map<Severity, List<String>> cvesBySeverity, Severity severity) {
        return cvesBySeverity.getOrDefault(severity, List.of()).size();
    }

    /**
     * Extracts all the technology versions disclosed in the given response headers.
     *
     * @param header the response header to examine
     * @return the versions found, in technology then header order, empty if none
     */
    static List<DetectedVersion> getVersions(HttpResponseHeader header) {
        return Stream.of(Technology.values())
                .flatMap(
                        tech ->
                                header.getHeaders().stream()
                                        .flatMap(field -> getVersions(tech, field)))
                .toList();
    }

    private static Stream<DetectedVersion> getVersions(Technology tech, HttpHeaderField field) {
        String value = field.getValue();
        return tech.versionPattern
                .matcher(value)
                .results()
                .map(
                        r ->
                                new DetectedVersion(
                                        tech,
                                        field.getName(),
                                        r.group(1),
                                        r.group(),
                                        getDistribution(value.substring(r.end()), value)));
    }

    /**
     * The distribution packaging the version, {@code null} if none is evident: the one named in a
     * comment right after the version (e.g. {@code (Ubuntu)}), else a package suffix (e.g. {@code
     * -4ubuntu2.19}), else one named in a comment elsewhere in the header, as a header such as
     * {@code Apache/2.4.41 (Ubuntu) PHP/7.4.3} describes one installation.
     *
     * @param afterVersion the header value after the version
     * @param header the whole header value
     * @return the distribution name or package suffix, or {@code null}
     */
    static String getDistribution(String afterVersion, String header) {
        Matcher comment = VERSION_COMMENT.matcher(afterVersion);
        if (comment.find()) {
            String distribution = getDistributionName(comment.group(1));
            if (distribution != null) {
                return distribution;
            }
        }
        Matcher suffix = VERSION_SUFFIX.matcher(afterVersion);
        if (suffix.find() && DISTRIBUTION_SUFFIX.matcher(suffix.group()).find()) {
            return suffix.group();
        }
        Matcher anyComment = HEADER_COMMENT.matcher(header);
        while (anyComment.find()) {
            String distribution = getDistributionName(anyComment.group(1));
            if (distribution != null) {
                return distribution;
            }
        }
        return null;
    }

    private static String getDistributionName(String comment) {
        Matcher distribution = DISTRIBUTION.matcher(comment);
        return distribution.find() ? distribution.group() : null;
    }

    private static KnownVulnerabilities getKnownVulnerabilities(Technology tech) {
        return KNOWN_VULNERABILITIES.computeIfAbsent(tech, Technology::loadKnownVulnerabilities);
    }

    /**
     * Sets the file to load the known vulnerabilities of the given technology from, instead of the
     * one bundled with the add-on.
     *
     * @param tech the technology
     * @param path the file to load
     */
    static void setKnownVulnerabilitiesFile(Technology tech, Path path) {
        KNOWN_VULNERABILITIES.put(tech, KnownVulnerabilities.load(path));
        allAlertTags = null;
    }

    /**
     * Returns the known vulnerabilities affecting the given version of the given technology, most
     * severe first.
     *
     * @param tech the technology
     * @param version the version, e.g. {@code 8.1.2}
     * @return the matching vulnerabilities, empty if none
     */
    static List<Vulnerability> getKnownVulnerabilities(Technology tech, String version) {
        return getKnownVulnerabilities(tech).getVulnerabilities(version);
    }

    /**
     * Forgets the sites already alerted on, so that they can be alerted on again. Called when the
     * session changes.
     */
    static void clear() {
        ALERTED.clear();
    }

    /** Forgets the known vulnerabilities loaded so far, so that the bundled ones are used again. */
    static void resetKnownVulnerabilities() {
        KNOWN_VULNERABILITIES.clear();
        allAlertTags = null;
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    /**
     * {@inheritDoc}
     *
     * <p>Returns the static tags plus a CVE tag for every known vulnerability of every technology.
     * The alerts raised carry only the CVE tags of the vulnerabilities which apply.
     */
    @Override
    public Map<String, String> getAlertTags() {
        Map<String, String> tags = allAlertTags;
        if (tags == null) {
            Map<String, String> all = new HashMap<>(STATIC_ALERT_TAGS);
            for (Technology tech : Technology.values()) {
                getKnownVulnerabilities(tech)
                        .vulnerabilities()
                        .forEach(v -> CommonAlertTag.putCve(all, v.cve()));
            }
            tags = Collections.unmodifiableMap(all);
            allAlertTags = tags;
        }
        return tags;
    }

    @Override
    public List<Alert> getExampleAlerts() {
        Vulnerability phpExample =
                new Vulnerability(
                        "CVE-2024-4577",
                        "GHSA-3qgc-jrrr-25jv",
                        "PHP RCE: A Bypass of CVE-2012-1823, Argument Injection in PHP-CGI",
                        "",
                        "high",
                        null,
                        null,
                        List.of(new VersionRange("8.1.0", "8.1.29", false)),
                        List.of(
                                "https://github.com/php/php-src/security/advisories/GHSA-3qgc-jrrr-25jv"),
                        "2024-09-28",
                        PhpAdvisories.SOURCE_GENERATED);
        Vulnerability apacheExample =
                new Vulnerability(
                        "CVE-2021-41773",
                        null,
                        "Path traversal and file disclosure vulnerability in Apache HTTP Server 2.4.49",
                        "",
                        "critical",
                        null,
                        null,
                        List.of(new VersionRange("2.4.49", "2.4.50", false)),
                        List.of(
                                "https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2021-41773"),
                        "2021-10-05",
                        ApacheHttpdAdvisories.SOURCE_GENERATED);
        return List.of(
                exampleAlert(
                        new DetectedVersion(Technology.PHP, "X-Powered-By", "8.1.2", "PHP/8.1.2"),
                        phpExample),
                exampleAlert(
                        new DetectedVersion(Technology.PHP, "X-Powered-By", "8.1", "PHP/8.1"),
                        phpExample),
                exampleAlert(
                        new DetectedVersion(Technology.APACHE, "Server", "2.4.49", "Apache/2.4.49"),
                        apacheExample),
                exampleAlert(
                        new DetectedVersion(Technology.APACHE, "Server", "2.4", "Apache/2.4"),
                        apacheExample));
    }

    /** An example alert of the technology, carrying the tags of all the technologies. */
    private Alert exampleAlert(DetectedVersion version, Vulnerability vulnerability) {
        return buildAlert(version, List.of(vulnerability))
                .setTags(new HashMap<>(getAlertTags()))
                .build();
    }
}
