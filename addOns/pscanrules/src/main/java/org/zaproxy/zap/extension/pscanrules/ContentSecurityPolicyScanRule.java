/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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

import com.shapesecurity.salvation2.Directives.SourceExpressionDirective;
import com.shapesecurity.salvation2.FetchDirectiveKind;
import com.shapesecurity.salvation2.Policy;
import com.shapesecurity.salvation2.Policy.PolicyErrorConsumer;
import com.shapesecurity.salvation2.PolicyInOrigin;
import com.shapesecurity.salvation2.URLs.URI;
import com.shapesecurity.salvation2.URLs.URLWithScheme;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.BiPredicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import net.htmlparser.jericho.Source;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * Content Security Policy Header passive scan rule https://github.com/zaproxy/zaproxy/issues/527
 * Meant to complement the CSP Header Missing passive scan rule
 *
 * <p>TODO: Add handling for CSP via META tag. See
 * https://github.com/shapesecurity/salvation/issues/149 for info on combining CSP policies
 *
 * @author kingthorin+owaspzap@gmail.com
 */
public class ContentSecurityPolicyScanRule extends PluginPassiveScanner {

    private static final String MESSAGE_PREFIX = "pscanrules.csp.";
    private static final int PLUGIN_ID = 10055;

    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
                    CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG);

    private static final Logger LOGGER = LogManager.getLogger(ContentSecurityPolicyScanRule.class);

    private static final String HTTP_HEADER_CSP = "Content-Security-Policy";
    private static final String HTTP_HEADER_XCSP = "X-Content-Security-Policy";
    private static final String HTTP_HEADER_WEBKIT_CSP = "X-WebKit-CSP";

    // Per:
    // https://developers.google.com/web/fundamentals/security/csp#policy_applies_to_a_wide_variety_of_resources as of 20200618
    private static final List<String> DIRECTIVES_WITHOUT_FALLBACK =
            Arrays.asList(
                    "base-uri",
                    "form-action",
                    "frame-ancestors",
                    "plugin-types",
                    "report-uri",
                    "sandbox");
    private static final List<String> ALLOWED_DIRECTIVES =
            Arrays.asList(
                    // TODO: Remove once https://github.com/shapesecurity/salvation/issues/232 is
                    // addressed
                    "require-trusted-types-for", "trusted-types");

    private static final String RAND_FQDN = "7963124546083337415.owasp.org";
    private static final Optional<URLWithScheme> HTTP_URI =
            Optional.of(URI.parseURI("http://" + RAND_FQDN).get());
    private static final Optional<URLWithScheme> HTTPS_URI =
            Optional.of(URI.parseURI("https://" + RAND_FQDN).get());

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        boolean cspHeaderFound = false;

        LOGGER.debug("Start {} : {}", id, msg.getRequestHeader().getURI());

        long start = System.currentTimeMillis();

        if (!msg.getResponseHeader().isHtml()
                && !AlertThreshold.LOW.equals(this.getAlertThreshold())) {
            // Only really applies to HTML responses, but also check everything on Low threshold
            return;
        }

        // Content-Security-Policy is supported by Chrome 25+, Firefox 23+,
        // Safari 7+, Edge but not Internet Explorer
        List<String> cspOptions = msg.getResponseHeader().getHeaderValues(HTTP_HEADER_CSP);
        if (!cspOptions.isEmpty()) {
            cspHeaderFound = true;
        }

        checkXcsp(msg, cspHeaderFound);
        checkXWebkitCsp(msg, cspHeaderFound);

        if (cspHeaderFound) {

            List<PolicyError> observedErrors = new ArrayList<>();
            PolicyErrorConsumer consumer =
                    (severity, message, directiveIndex, valueIndex) -> {
                        // Skip notices for directives that Salvation doesn't handle
                        if (ALLOWED_DIRECTIVES.stream().noneMatch(message::contains)) {
                            observedErrors.add(
                                    new PolicyError(severity, message, directiveIndex, valueIndex));
                        }
                    };

            for (String csp : cspOptions) {
                Policy policy = parsePolicy(csp, consumer, msg, id);
                if (policy == null) {
                    continue;
                }

                if (!observedErrors.isEmpty()) {
                    checkObservedErrors(observedErrors, msg, csp);
                }

                List<String> allowedWildcardSources = getAllowedWildcardSources(csp);
                if (!allowedWildcardSources.isEmpty()) {
                    checkWildcardSources(allowedWildcardSources, msg, csp);
                }

                PolicyInOrigin p = new PolicyInOrigin(policy, URI.parseURI(RAND_FQDN).orElse(null));
                if (p.allowsUnsafeInlineScript()) {
                    buildScriptUnsafeInlineAlert(getHeaderField(msg, HTTP_HEADER_CSP).get(0), csp)
                            .raise();
                }

                if (p.allowsUnsafeInlineStyle()) {
                    buildStyleUnsafeInlineAlert(getHeaderField(msg, HTTP_HEADER_CSP).get(0), csp)
                            .raise();
                }

                if (allowsUnsafeHashes(policy, FetchDirectiveKind.ScriptSrc)) {
                    buildScriptUnsafeHashAlert(getHeaderField(msg, HTTP_HEADER_CSP).get(0), csp)
                            .raise();
                }

                if (allowsUnsafeHashes(policy, FetchDirectiveKind.StyleSrc)) {
                    buildStyleUnsafeHashAlert(getHeaderField(msg, HTTP_HEADER_CSP).get(0), csp)
                            .raise();
                }
            }
        }

        LOGGER.debug("\tScan of record {} took {} ms", id, System.currentTimeMillis() - start);
    }

    private void checkXcsp(HttpMessage msg, boolean cspHeaderFound) {
        // X-Content-Security-Policy is an older header, supported by Firefox
        // 4.0+, and IE 10+ (in a limited fashion)
        List<String> xcspOptions = msg.getResponseHeader().getHeaderValues(HTTP_HEADER_XCSP);
        if (!xcspOptions.isEmpty()) {
            buildXcspAlert(
                            cspHeaderFound ? Alert.RISK_INFO : Alert.RISK_LOW,
                            getHeaderField(msg, HTTP_HEADER_XCSP).get(0),
                            xcspOptions.get(0))
                    .raise();
        }
    }

    private void checkXWebkitCsp(HttpMessage msg, boolean cspHeaderFound) {
        // X-WebKit-CSP is supported by Chrome 14+, and Safari 6+
        List<String> xwkcspOptions =
                msg.getResponseHeader().getHeaderValues(HTTP_HEADER_WEBKIT_CSP);
        if (!xwkcspOptions.isEmpty()) {
            buildWebkitCspAlert(
                            cspHeaderFound ? Alert.RISK_INFO : Alert.RISK_LOW,
                            getHeaderField(msg, HTTP_HEADER_WEBKIT_CSP).get(0),
                            xwkcspOptions.get(0))
                    .raise();
        }
    }

    private Policy parsePolicy(String csp, PolicyErrorConsumer consumer, HttpMessage msg, int id) {
        try {
            return Policy.parseSerializedCSP(csp, consumer);
        } catch (IllegalArgumentException iae) {
            boolean warn = true;
            if (iae.getMessage().contains("not ascii")) {
                buildMalformedAlert(
                                getHeaderField(msg, HTTP_HEADER_CSP).get(0),
                                csp,
                                getNonasciiCharacters(csp))
                        .raise();
                warn = false;
            }

            if (warn) {
                LOGGER.warn("CSP Found but not fully parsed, in message {}.", id);
            }
        }
        return null;
    }

    private void checkObservedErrors(
            List<PolicyError> observedErrors, HttpMessage msg, String csp) {
        String cspNoticesString = getCspNoticesString(observedErrors);
        int noticesRisk;

        if (cspNoticesString.contains(
                        Constant.messages.getString(MESSAGE_PREFIX + "notices.errors"))
                || cspNoticesString.contains(
                        Constant.messages.getString(MESSAGE_PREFIX + "notices.warnings"))) {
            noticesRisk = Alert.RISK_LOW;
        } else {
            noticesRisk = Alert.RISK_INFO;
        }
        buildNoticesAlert(
                        noticesRisk,
                        getHeaderField(msg, HTTP_HEADER_CSP).get(0),
                        csp,
                        cspNoticesString)
                .raise();
    }

    private void checkWildcardSources(
            List<String> allowedWildcardSources, HttpMessage msg, String csp) {
        List<String> allowedDirectivesWithoutFallback =
                allowedWildcardSources.stream()
                        .distinct()
                        .filter(DIRECTIVES_WITHOUT_FALLBACK::contains)
                        .collect(Collectors.toList());
        String allowedWildcardSrcs = String.join(", ", allowedWildcardSources);
        String wildcardSrcOtherInfo =
                Constant.messages.getString(
                        MESSAGE_PREFIX + "wildcard.otherinfo", allowedWildcardSrcs);
        if (!allowedDirectivesWithoutFallback.isEmpty()) {
            wildcardSrcOtherInfo +=
                    Constant.messages.getString(
                            "pscanrules.csp.otherinfo.extended",
                            String.join(", ", allowedDirectivesWithoutFallback));
        }
        buildWildcardAlert(getHeaderField(msg, HTTP_HEADER_CSP).get(0), csp, wildcardSrcOtherInfo)
                .raise();
    }

    private static boolean allowsUnsafeHashes(Policy policy, FetchDirectiveKind source) {
        Optional<SourceExpressionDirective> fetchDirective = policy.getFetchDirective(source);
        if (fetchDirective.isPresent()) {
            SourceExpressionDirective kind = fetchDirective.get();
            return kind.unsafeHashes();
        }
        return false;
    }

    private String getCspNoticesString(List<PolicyError> notices) {
        if (notices.isEmpty()) {
            return "";
        }

        char newLine = '\n';
        StringBuilder returnSb = new StringBuilder();

        List<PolicyError> errorsList = getNotices(notices, Policy.Severity.Error);
        if (!errorsList.isEmpty()) {
            returnSb.append(Constant.messages.getString(MESSAGE_PREFIX + "notices.errors"))
                    .append(newLine);
            for (PolicyError pe : errorsList) {
                returnSb.append(pe.getMessage()).append(newLine);
            }
        }

        List<PolicyError> warnList = getNotices(notices, Policy.Severity.Warning);
        if (!warnList.isEmpty()) {
            returnSb.append(Constant.messages.getString(MESSAGE_PREFIX + "notices.warnings"))
                    .append(newLine);
            for (PolicyError pe : warnList) {
                returnSb.append(pe.getMessage()).append(newLine);
            }
        }

        List<PolicyError> infoList = getNotices(notices, Policy.Severity.Info);
        if (!infoList.isEmpty()) {
            returnSb.append(Constant.messages.getString(MESSAGE_PREFIX + "notices.infoitems"))
                    .append(newLine);
            for (PolicyError pe : infoList) {
                returnSb.append(pe.getMessage()).append(newLine);
            }
        }
        return returnSb.toString();
    }

    private static List<PolicyError> getNotices(
            List<PolicyError> notices, Policy.Severity severity) {
        List<PolicyError> noticeList = new ArrayList<>();
        for (PolicyError polErr : notices) {
            if (severity.equals(polErr.getSeverity())) {
                noticeList.add(polErr);
            }
        }
        return noticeList;
    }

    /**
     * Extracts a list of headers, and returns them without changing their cases.
     *
     * @param msg HTTP Response message
     * @param header The header field(s) to be found
     * @return list of the matched headers
     */
    private List<String> getHeaderField(HttpMessage msg, String header) {
        List<String> matchedHeaders = new ArrayList<>();
        String headers = msg.getResponseHeader().toString();
        String[] headerElements = headers.split("\\r\\n");
        Pattern pattern = Pattern.compile("^" + header, Pattern.CASE_INSENSITIVE);
        for (String hdr : headerElements) {
            Matcher matcher = pattern.matcher(hdr);
            if (matcher.find()) {
                String match = matcher.group();
                matchedHeaders.add(match);
            }
        }
        return matchedHeaders;
    }

    private List<String> getAllowedWildcardSources(String policyText) {

        List<String> allowedSources = new ArrayList<>();
        Policy pol = Policy.parseSerializedCSP(policyText, PolicyErrorConsumer.ignored);

        if (checkPolicy(pol::allowsExternalScript)) {
            allowedSources.add("script-src");
        }
        if (checkPolicy(pol::allowsExternalStyle)) {
            allowedSources.add("style-src");
        }
        if (checkPolicy(pol::allowsImage)) {
            allowedSources.add("img-src");
        }
        if (checkPolicy(pol::allowsConnection)) {
            allowedSources.add("connect-src");
        }
        if (checkPolicy(pol::allowsFrame)) {
            allowedSources.add("frame-src");
        }
        if (checkPolicy(pol::allowsFrameAncestor)) {
            allowedSources.add("frame-ancestors");
        }
        if (checkPolicy(pol::allowsFont)) {
            allowedSources.add("font-src");
        }
        if (checkPolicy(pol::allowsMedia)) {
            allowedSources.add("media-src");
        }
        if (checkPolicy(pol::allowsObject)) {
            allowedSources.add("object-src");
        }
        if (checkPolicy(pol::allowsApplicationManifest)) {
            allowedSources.add("manifest-src");
        }
        if (checkPolicy(pol::allowsWorker)) {
            allowedSources.add("worker-src");
        }
        if (checkPolicy(pol::allowsPrefetch)) {
            allowedSources.add("prefetch-src");
        }
        if (checkPolicy(pol::allowsFormAction)) {
            allowedSources.add("form-action");
        }

        return allowedSources;
    }

    private static boolean checkPolicy(AllowsFormActionCheck function) {
        return function.apply(HTTP_URI, Optional.of(false), Optional.empty(), Optional.empty())
                || function.apply(
                        HTTPS_URI, Optional.of(false), Optional.empty(), Optional.empty());
    }

    private static boolean checkPolicy(AllowsExternalScriptCheck function) {
        return function.apply(
                        Optional.empty(),
                        Optional.empty(),
                        HTTP_URI,
                        Optional.empty(),
                        Optional.empty())
                || function.apply(
                        Optional.empty(),
                        Optional.empty(),
                        HTTPS_URI,
                        Optional.empty(),
                        Optional.empty());
    }

    private static boolean checkPolicy(AllowsExternalStyleCheck function) {
        return function.apply(Optional.empty(), HTTP_URI, Optional.empty())
                || function.apply(Optional.empty(), HTTPS_URI, Optional.empty());
    }

    private static boolean checkPolicy(
            BiPredicate<Optional<URLWithScheme>, Optional<URLWithScheme>> predicate) {
        return predicate.test(HTTP_URI, Optional.empty())
                || predicate.test(HTTPS_URI, Optional.empty());
    }

    private static String getNonasciiCharacters(String csp) {
        return csp.codePoints()
                .filter(c -> !isAsciiPrintable(c))
                .mapToObj(c -> String.valueOf((char) c))
                .collect(Collectors.joining());
    }

    private static boolean isAsciiPrintable(int ch) {
        return ch >= 32 && ch < 127;
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    public int getCweId() {
        return 693; // CWE-693: Protection Mechanism Failure
    }

    public int getWascId() {
        return 15; // WASC-15: Application Misconfiguration
    }

    private AlertBuilder getBuilder(String name, String alertRef) {
        String alertName = StringUtils.isEmpty(name) ? getName() : getName() + ": " + name;
        return newAlert()
                .setName(alertName)
                .setConfidence(Alert.CONFIDENCE_HIGH)
                .setDescription(Constant.messages.getString(MESSAGE_PREFIX + "desc"))
                .setSolution(getSolution())
                .setReference(getReference())
                .setCweId(getCweId())
                .setWascId(getWascId())
                .setAlertRef(PLUGIN_ID + "-" + alertRef);
    }

    private AlertBuilder buildXcspAlert(int risk, String param, String evidence) {
        return getBuilder(Constant.messages.getString(MESSAGE_PREFIX + "xcsp.name"), "1")
                .setRisk(risk)
                .setParam(param)
                .setEvidence(evidence)
                .setOtherInfo(Constant.messages.getString(MESSAGE_PREFIX + "xcsp.otherinfo"));
    }

    private AlertBuilder buildWebkitCspAlert(int risk, String param, String evidence) {
        return getBuilder(Constant.messages.getString(MESSAGE_PREFIX + "xwkcsp.name"), "2")
                .setRisk(risk)
                .setParam(param)
                .setEvidence(evidence)
                .setOtherInfo(Constant.messages.getString(MESSAGE_PREFIX + "xwkcsp.otherinfo"));
    }

    private AlertBuilder buildNoticesAlert(
            int risk, String param, String evidence, String otherinfo) {
        return getBuilder(Constant.messages.getString(MESSAGE_PREFIX + "notices.name"), "3")
                .setRisk(risk)
                .setParam(param)
                .setEvidence(evidence)
                .setOtherInfo(otherinfo);
    }

    private AlertBuilder buildWildcardAlert(String param, String evidence, String otherinfo) {
        return getBuilder(Constant.messages.getString(MESSAGE_PREFIX + "wildcard.name"), "4")
                .setRisk(Alert.RISK_MEDIUM)
                .setParam(param)
                .setEvidence(evidence)
                .setOtherInfo(otherinfo);
    }

    private AlertBuilder buildScriptUnsafeInlineAlert(String param, String evidence) {
        return getBuilder(
                        Constant.messages.getString(MESSAGE_PREFIX + "scriptsrc.unsafe.name"), "5")
                .setRisk(Alert.RISK_MEDIUM)
                .setParam(param)
                .setEvidence(evidence)
                .setOtherInfo(
                        Constant.messages.getString(MESSAGE_PREFIX + "scriptsrc.unsafe.otherinfo"));
    }

    private AlertBuilder buildStyleUnsafeInlineAlert(String param, String evidence) {
        return getBuilder(Constant.messages.getString(MESSAGE_PREFIX + "stylesrc.unsafe.name"), "6")
                .setRisk(Alert.RISK_MEDIUM)
                .setParam(param)
                .setEvidence(evidence)
                .setOtherInfo(
                        Constant.messages.getString(MESSAGE_PREFIX + "stylesrc.unsafe.otherinfo"));
    }

    private AlertBuilder buildScriptUnsafeHashAlert(String param, String evidence) {
        return getBuilder(
                        Constant.messages.getString(
                                MESSAGE_PREFIX + "scriptsrc.unsafe.hashes.name"),
                        "7")
                .setRisk(Alert.RISK_MEDIUM)
                .setParam(param)
                .setEvidence(evidence)
                .setOtherInfo(
                        Constant.messages.getString(
                                MESSAGE_PREFIX + "scriptsrc.unsafe.hashes.otherinfo"))
                .setReference(
                        Constant.messages.getString(
                                MESSAGE_PREFIX + "scriptsrc.unsafe.hashes.refs"));
    }

    private AlertBuilder buildStyleUnsafeHashAlert(String param, String evidence) {
        return getBuilder(
                        Constant.messages.getString(MESSAGE_PREFIX + "stylesrc.unsafe.hashes.name"),
                        "8")
                .setRisk(Alert.RISK_MEDIUM)
                .setParam(param)
                .setEvidence(evidence)
                .setOtherInfo(
                        Constant.messages.getString(
                                MESSAGE_PREFIX + "stylesrc.unsafe.hashes.otherinfo"))
                .setReference(
                        Constant.messages.getString(
                                MESSAGE_PREFIX + "stylesrc.unsafe.hashes.refs"));
    }

    private AlertBuilder buildMalformedAlert(String param, String evidence, String badChars) {
        return getBuilder(Constant.messages.getString(MESSAGE_PREFIX + "malformed.name"), "9")
                .setRisk(Alert.RISK_MEDIUM)
                .setParam(param)
                .setEvidence(evidence)
                .setOtherInfo(
                        Constant.messages.getString(
                                MESSAGE_PREFIX + "malformed.otherinfo", badChars));
    }

    @Override
    public List<Alert> getExampleAlerts() {
        List<Alert> alerts = new ArrayList<>();
        alerts.add(buildXcspAlert(Alert.RISK_LOW, "default-src 'self'", HTTP_HEADER_XCSP).build());
        alerts.add(
                buildWebkitCspAlert(Alert.RISK_LOW, "default-src 'self'", HTTP_HEADER_WEBKIT_CSP)
                        .build());
        alerts.add(
                buildNoticesAlert(
                                Alert.RISK_LOW,
                                HTTP_HEADER_CSP,
                                "default-src none; report-to csp-endpoint ",
                                "Warnings:\\nThis host name is unusual, and likely meant to be a keyword that is missing the required quotes: 'none'.")
                        .build());
        alerts.add(
                buildWildcardAlert(
                                HTTP_HEADER_CSP,
                                "connect-src *; default-src 'self'; form-action 'none'; frame-ancestors 'self'",
                                Constant.messages.getString(
                                        MESSAGE_PREFIX + "wildcard.otherinfo", "connect-src"))
                        .build());
        alerts.add(
                buildScriptUnsafeInlineAlert(HTTP_HEADER_CSP, "script-src 'unsafe-inline'")
                        .build());
        alerts.add(
                buildStyleUnsafeInlineAlert(HTTP_HEADER_CSP, "style-src 'unsafe-inline'").build());
        alerts.add(
                buildScriptUnsafeHashAlert(
                                HTTP_HEADER_CSP,
                                "default-src 'self'; script-src 'unsafe-hashes' 'sha256-jzgBGA4UWFFmpOBq0JpdsySukE1FrEN5bUpoK8Z29fY='")
                        .build());
        alerts.add(
                buildStyleUnsafeHashAlert(
                                HTTP_HEADER_CSP,
                                "default-src 'self'; style-src 'unsafe-hashes' 'sha256-xyz4zkCjuC3lZcD2UmnqDG0vurmq12W/XKM5Vd0+MlQ='")
                        .build());
        alerts.add(
                buildMalformedAlert(
                                HTTP_HEADER_CSP,
                                "\"default-src ‘self’ 'unsafe-eval' 'unsafe-inline' www.example.net;\"",
                                "‘’")
                        .build());
        return alerts;
    }

    static class PolicyError {
        final Policy.Severity severity;
        final String message;
        final int directiveIndex;
        final int valueIndex;

        PolicyError(Policy.Severity severity, String message, int directiveIndex, int valueIndex) {
            this.severity = severity;
            this.message = message;
            this.directiveIndex = directiveIndex;
            this.valueIndex = valueIndex;
        }

        public Policy.Severity getSeverity() {
            return severity;
        }

        public String getMessage() {
            return message;
        }

        @Override
        public String toString() {
            return "("
                    + this.severity.name()
                    + ") "
                    + this.message
                    + " at directive "
                    + this.directiveIndex
                    + " at value "
                    + this.valueIndex;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            PolicyError that = (PolicyError) o;
            return directiveIndex == that.directiveIndex
                    && valueIndex == that.valueIndex
                    && severity == that.severity
                    && message.equals(that.message);
        }

        @Override
        public int hashCode() {
            return Objects.hash(severity, message, directiveIndex, valueIndex);
        }
    }

    private interface AllowsExternalScriptCheck {
        boolean apply(
                Optional<String> nonce,
                Optional<String> integrity,
                Optional<URLWithScheme> scriptUrl,
                Optional<Boolean> parserInserted,
                Optional<URLWithScheme> origin);
    }

    private interface AllowsExternalStyleCheck {
        boolean apply(
                Optional<String> nonce,
                Optional<URLWithScheme> styleUrl,
                Optional<URLWithScheme> origin);
    }

    private interface AllowsFormActionCheck {
        boolean apply(
                Optional<URLWithScheme> to,
                Optional<Boolean> redirected,
                Optional<URLWithScheme> redirectedTo,
                Optional<URLWithScheme> origin);
    }
}
