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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.BiPredicate;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.htmlunit.csp.FetchDirectiveKind;
import org.htmlunit.csp.Policy;
import org.htmlunit.csp.Policy.PolicyErrorConsumer;
import org.htmlunit.csp.Policy.PolicyListErrorConsumer;
import org.htmlunit.csp.PolicyList;
import org.htmlunit.csp.PolicyListInOrigin;
import org.htmlunit.csp.directive.SourceExpressionDirective;
import org.htmlunit.csp.url.URI;
import org.htmlunit.csp.url.URLWithScheme;
import org.htmlunit.csp.value.Hash;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.addon.commonlib.http.HttpFieldsNames;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * Content Security Policy Header passive scan rule https://github.com/zaproxy/zaproxy/issues/527
 * Meant to complement the CSP Header Missing passive scan rule
 */
public class ContentSecurityPolicyScanRule extends PluginPassiveScanner
        implements CommonPassiveScanRuleInfo {

    private static final String MESSAGE_PREFIX = "pscanrules.csp.";
    private static final int PLUGIN_ID = 10055;

    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2025_A02_SEC_MISCONFIG,
                                CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
                                CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG,
                                CommonAlertTag.SYSTEMIC));
        alertTags.put(PolicyTag.PENTEST.getTag(), "");
        alertTags.put(PolicyTag.DEV_STD.getTag(), "");
        alertTags.put(PolicyTag.QA_STD.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    private static final Logger LOGGER = LogManager.getLogger(ContentSecurityPolicyScanRule.class);

    private static final String HTTP_HEADER_XCSP = "X-Content-Security-Policy";
    private static final String HTTP_HEADER_WEBKIT_CSP = "X-WebKit-CSP";
    private static final String FRAME_ANCESTORS = "frame-ancestors";
    // Per:
    // https://developers.google.com/web/fundamentals/security/csp#policy_applies_to_a_wide_variety_of_resources as of 20200618
    // 20250131 "base-uri" is not included. Per MDN if it isn't specified then the <base> value is
    // used, if no base value then location.href "plugin-types" is not included, the directive has
    // been deprecated. "report-uri" is not included as it has no literal impact. "sandbox" does not
    // fallback, but excluding it does not necessarily make anything 'more' vulnerable, it's use
    // simply allows more detailed control of what embedded content can do.
    private static final List<String> DIRECTIVES_WITHOUT_FALLBACK =
            List.of("form-action", FRAME_ANCESTORS);

    private static final String RAND_FQDN = "7963124546083337415.owasp.org";
    private static final Optional<URLWithScheme> HTTP_URI =
            Optional.of(URI.parseURI("http://" + RAND_FQDN).get());
    private static final Optional<URLWithScheme> HTTPS_URI =
            Optional.of(URI.parseURI("https://" + RAND_FQDN).get());

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        LOGGER.debug("Start {} : {}", id, msg.getRequestHeader().getURI());

        long start = System.currentTimeMillis();

        if (!msg.getResponseHeader().isHtml()
                && !AlertThreshold.LOW.equals(this.getAlertThreshold())) {
            // Only really applies to HTML responses, but also check everything on Low threshold
            return;
        }

        // Content-Security-Policy is supported by Chrome 25+, Firefox 23+,
        // Safari 7+, Edge but not Internet Explorer
        List<String> cspOptions =
                msg.getResponseHeader().getHeaderValues(HttpFieldsNames.CONTENT_SECURITY_POLICY);
        boolean cspHeaderFound = !cspOptions.isEmpty();

        checkXcsp(msg, cspHeaderFound);
        checkXWebkitCsp(msg, cspHeaderFound);

        List<Policy> enforcedPolicies = new ArrayList<>();
        List<String> enforcedPolicyTexts = new ArrayList<>();
        boolean headerContributedPolicy = false;

        for (String csp : cspOptions) {
            List<PolicyError> observedErrors = new ArrayList<>();
            PolicyListErrorConsumer consumer =
                    (severity, message, policyIndex, directiveIndex, valueIndex) ->
                            observedErrors.add(
                                    new PolicyError(severity, message, directiveIndex, valueIndex));
            PolicyList parsed = parsePolicyList(csp, consumer, msg, id);
            if (parsed == null) {
                continue;
            }
            if (!observedErrors.isEmpty()) {
                checkObservedErrors(observedErrors, msg, csp, false);
            }
            if (!parsed.getPolicies().isEmpty()) {
                enforcedPolicies.addAll(parsed.getPolicies());
                enforcedPolicyTexts.add(csp);
                headerContributedPolicy = true;
            }
        }

        for (Element element :
                source.getAllElements(HTMLElementName.META).stream()
                        .filter(e -> !StringUtils.isBlank(e.getAttributeValue("http-equiv")))
                        .toList()) {
            String metaField = element.getAttributeValue("http-equiv");
            String metaPolicy = element.getAttributeValue("content");
            if (!HttpFieldsNames.CONTENT_SECURITY_POLICY.equalsIgnoreCase(metaField)
                    || StringUtils.isBlank(metaPolicy)) {
                continue;
            }
            List<PolicyError> metaObservedErrors = new ArrayList<>();
            PolicyErrorConsumer metaConsumer =
                    (severity, message, directiveIndex, valueIndex) ->
                            metaObservedErrors.add(
                                    new PolicyError(severity, message, directiveIndex, valueIndex));
            Policy parsedMetaPolicy = parsePolicy(metaPolicy, metaConsumer, true, msg, id);
            if (parsedMetaPolicy == null) {
                continue;
            }
            checkObservedErrors(metaObservedErrors, msg, metaPolicy, true);
            if (parsedMetaPolicy.sandbox().isPresent()
                    || parsedMetaPolicy.frameAncestors().isPresent()
                    || parsedMetaPolicy.reportUri().isPresent()) {
                buildBadMetaAlert(metaField, metaPolicy).raise();
            }
            enforcedPolicies.add(parsedMetaPolicy);
            enforcedPolicyTexts.add(metaPolicy);
        }

        if (!enforcedPolicies.isEmpty()) {
            checkEffectivePolicies(
                    msg, enforcedPolicies, enforcedPolicyTexts, headerContributedPolicy);
        }

        LOGGER.debug("\tScan of record {} took {} ms", id, System.currentTimeMillis() - start);
    }

    private void checkEffectivePolicies(
            HttpMessage msg,
            List<Policy> enforcedPolicies,
            List<String> enforcedPolicyTexts,
            boolean headerContributedPolicy) {
        PolicyList policyList = new PolicyList(enforcedPolicies);
        PolicyListInOrigin bound = new PolicyListInOrigin(policyList, HTTP_URI.get());
        String evidence = enforcedPolicyTexts.get(0);
        String param =
                headerContributedPolicy
                        ? getHeaderField(msg, HttpFieldsNames.CONTENT_SECURITY_POLICY).get(0)
                        : HttpFieldsNames.CONTENT_SECURITY_POLICY;
        String multiPolicyInfo =
                buildMultiPolicyOtherInfo(enforcedPolicies.size(), enforcedPolicyTexts);

        List<String> allowedWildcardSources = getAllowedWildcardSources(policyList);
        checkWildcardSources(allowedWildcardSources, param, evidence, multiPolicyInfo);

        if (bound.allowsUnsafeInlineScript()) {
            buildScriptUnsafeInlineAlert(param, evidence, multiPolicyInfo).raise();
        }
        if (bound.allowsUnsafeInlineStyle()) {
            buildStyleUnsafeInlineAlert(param, evidence, multiPolicyInfo).raise();
        }
        if (isUnsafeHashesEffectivelyAllowed(policyList, FetchDirectiveKind.ScriptSrc)) {
            buildScriptUnsafeHashAlert(param, evidence, multiPolicyInfo).raise();
        }
        if (isUnsafeHashesEffectivelyAllowed(policyList, FetchDirectiveKind.StyleSrc)) {
            buildStyleUnsafeHashAlert(param, evidence, multiPolicyInfo).raise();
        }
        if (isEffectiveKeywordAllowed(
                policyList, FetchDirectiveKind.ScriptSrc, SourceExpressionDirective::unsafeEval)) {
            buildScriptUnsafeEvalAlert(param, evidence, multiPolicyInfo).raise();
        }
    }

    private void checkXcsp(HttpMessage msg, boolean cspHeaderFound) {
        // X-Content-Security-Policy is an older header, supported by Firefox
        // 4.0+, and IE 10+ (in a limited fashion)
        List<String> xcspOptions = msg.getResponseHeader().getHeaderValues(HTTP_HEADER_XCSP);
        if (!xcspOptions.isEmpty()) {
            getBuilder(
                            Constant.messages.getString(MESSAGE_PREFIX + "xcsp.name"),
                            "1",
                            getHeaderField(msg, HTTP_HEADER_XCSP).get(0),
                            xcspOptions.get(0),
                            cspHeaderFound ? Alert.RISK_INFO : Alert.RISK_LOW)
                    .setOtherInfo(Constant.messages.getString(MESSAGE_PREFIX + "xcsp.otherinfo"))
                    .raise();
        }
    }

    private void checkXWebkitCsp(HttpMessage msg, boolean cspHeaderFound) {
        // X-WebKit-CSP is supported by Chrome 14+, and Safari 6+
        List<String> xwkcspOptions =
                msg.getResponseHeader().getHeaderValues(HTTP_HEADER_WEBKIT_CSP);
        if (!xwkcspOptions.isEmpty()) {
            getBuilder(
                            Constant.messages.getString(MESSAGE_PREFIX + "xwkcsp.name"),
                            "2",
                            getHeaderField(msg, HTTP_HEADER_WEBKIT_CSP).get(0),
                            xwkcspOptions.get(0),
                            cspHeaderFound ? Alert.RISK_INFO : Alert.RISK_LOW)
                    .setOtherInfo(Constant.messages.getString(MESSAGE_PREFIX + "xwkcsp.otherinfo"))
                    .raise();
        }
    }

    private PolicyList parsePolicyList(
            String csp, PolicyListErrorConsumer consumer, HttpMessage msg, int id) {
        return parseWithErrorHandling(
                () -> Policy.parseSerializedCSPList(csp, consumer), csp, msg, id);
    }

    private Policy parsePolicy(
            String csp,
            PolicyErrorConsumer consumer,
            boolean deliveredViaMeta,
            HttpMessage msg,
            int id) {
        return parseWithErrorHandling(
                () -> Policy.parseSerializedCSP(csp, consumer, deliveredViaMeta), csp, msg, id);
    }

    private <T> T parseWithErrorHandling(Supplier<T> parser, String csp, HttpMessage msg, int id) {
        try {
            return parser.get();
        } catch (IllegalArgumentException iae) {
            handleParseException(iae, csp, msg, id);
        }
        return null;
    }

    private void handleParseException(
            IllegalArgumentException iae, String csp, HttpMessage msg, int id) {
        boolean warn = true;
        if (iae.getMessage().contains("not ascii")) {
            List<String> headerField = getHeaderField(msg, HttpFieldsNames.CONTENT_SECURITY_POLICY);
            String param =
                    headerField.isEmpty()
                            ? HttpFieldsNames.CONTENT_SECURITY_POLICY
                            : headerField.get(0);
            buildMalformedAlert(param, csp, getNonasciiCharacters(csp)).raise();
            warn = false;
        }

        if (warn) {
            LOGGER.warn("CSP Found but not fully parsed, in message {}.", id);
        }
    }

    private void checkObservedErrors(
            List<PolicyError> observedErrors, HttpMessage msg, String csp, boolean isMeta) {
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
        if (!cspNoticesString.isEmpty()) {
            getBuilder(
                            Constant.messages.getString(MESSAGE_PREFIX + "notices.name"),
                            "3",
                            isMeta
                                    ? HttpFieldsNames.CONTENT_SECURITY_POLICY
                                    : getHeaderField(msg, HttpFieldsNames.CONTENT_SECURITY_POLICY)
                                            .get(0),
                            csp,
                            noticesRisk)
                    .setOtherInfo(cspNoticesString)
                    .raise();
        }
    }

    private void checkWildcardSources(
            List<String> allowedWildcardSources,
            String param,
            String evidence,
            String multiPolicyInfo) {
        if (allowedWildcardSources.isEmpty()) {
            return;
        }
        List<String> allowedDirectivesWithoutFallback =
                allowedWildcardSources.stream()
                        .distinct()
                        .filter(DIRECTIVES_WITHOUT_FALLBACK::contains)
                        .toList();
        allowedWildcardSources.removeAll(DIRECTIVES_WITHOUT_FALLBACK);
        if (!allowedDirectivesWithoutFallback.isEmpty()) {
            buildNofallbackAlert(param, evidence, allowedDirectivesWithoutFallback, multiPolicyInfo)
                    .raise();
        }
        if (!allowedWildcardSources.isEmpty()) {
            String allowedWildcardSrcs = String.join(", ", allowedWildcardSources);
            String wildcardSrcOtherInfo =
                    appendMultiPolicyInfo(
                            Constant.messages.getString(
                                    MESSAGE_PREFIX + "wildcard.otherinfo", allowedWildcardSrcs),
                            multiPolicyInfo);
            buildWildcardAlert(param, evidence, wildcardSrcOtherInfo).raise();
        }
    }

    /**
     * Determines whether every policy effectively allows the given keyword for the given fetch
     * directive, resolving each policy's governing directive via the CSP fallback chain (e.g.
     * {@code script-src} falling back to {@code default-src}). A policy with no governing directive
     * in the chain is unrestricted and does not block the keyword. At least one policy must
     * actually declare the keyword, otherwise there is nothing to alert on.
     */
    private static boolean isEffectiveKeywordAllowed(
            PolicyList policyList,
            FetchDirectiveKind source,
            Predicate<SourceExpressionDirective> hasKeyword) {
        List<Optional<SourceExpressionDirective>> effectiveDirectives =
                policyList.getPolicies().stream()
                        .map(pol -> pol.getGoverningDirectiveForEffectiveDirective(source))
                        .toList();
        return effectiveDirectives.stream().anyMatch(d -> d.filter(hasKeyword).isPresent())
                && effectiveDirectives.stream().allMatch(d -> d.map(hasKeyword::test).orElse(true));
    }

    /**
     * Determines whether {@code 'unsafe-hashes'} is effectively allowed for the given fetch
     * directive across all policies: every restricted policy (per the CSP fallback chain) must
     * declare {@code 'unsafe-hashes'} and their hash sets must intersect, since a hash blocked by
     * any one policy is blocked overall.
     */
    private static boolean isUnsafeHashesEffectivelyAllowed(
            PolicyList policyList, FetchDirectiveKind source) {
        Set<Hash> commonHashes = null;
        for (Policy pol : policyList.getPolicies()) {
            Optional<SourceExpressionDirective> effective =
                    pol.getGoverningDirectiveForEffectiveDirective(source);
            if (effective.isEmpty()) {
                continue;
            }
            SourceExpressionDirective directive = effective.get();
            if (!directive.unsafeHashes() || directive.getHashes().isEmpty()) {
                return false;
            }
            if (commonHashes == null) {
                commonHashes = new HashSet<>(directive.getHashes());
            } else {
                commonHashes.retainAll(directive.getHashes());
            }
            if (commonHashes.isEmpty()) {
                return false;
            }
        }
        return commonHashes != null;
    }

    private static String getCspNoticesString(List<PolicyError> notices) {
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
    private static List<String> getHeaderField(HttpMessage msg, String header) {
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

    private static List<String> getAllowedWildcardSources(PolicyList pol) {

        List<String> allowedSources = new ArrayList<>();

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
            allowedSources.add(FRAME_ANCESTORS);
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
        if (checkPolicy(pol::allowsFormAction)) {
            allowedSources.add("form-action");
        }

        return allowedSources;
    }

    private static String buildMultiPolicyOtherInfo(int policyCount, List<String> policyTexts) {
        if (policyCount <= 1) {
            return "";
        }
        return Constant.messages.getString(
                MESSAGE_PREFIX + "multipolicy.otherinfo",
                policyCount,
                String.join("\n", policyTexts));
    }

    private static String appendMultiPolicyInfo(String otherInfo, String multiPolicyInfo) {
        if (StringUtils.isBlank(multiPolicyInfo)) {
            return otherInfo;
        }
        if (StringUtils.isBlank(otherInfo)) {
            return multiPolicyInfo;
        }
        return otherInfo + "\n" + multiPolicyInfo;
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

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    private AlertBuilder getBuilder(String name, String alertRef) {
        String alertName = StringUtils.isEmpty(name) ? getName() : getName() + ": " + name;
        return newAlert()
                .setName(alertName)
                .setConfidence(Alert.CONFIDENCE_HIGH)
                .setDescription(Constant.messages.getString(MESSAGE_PREFIX + "desc"))
                .setSolution(Constant.messages.getString(MESSAGE_PREFIX + "soln"))
                .setReference(Constant.messages.getString(MESSAGE_PREFIX + "refs"))
                .setCweId(693) // CWE-693: Protection Mechanism Failure
                .setWascId(15) // WASC-15: Application Misconfiguration
                .setAlertRef(PLUGIN_ID + "-" + alertRef);
    }

    private AlertBuilder getBuilder(
            String name, String alertRef, String param, String evidence, int risk) {
        return getBuilder(name, alertRef).setRisk(risk).setParam(param).setEvidence(evidence);
    }

    private AlertBuilder buildWildcardAlert(String param, String evidence, String otherinfo) {
        return getBuilder(
                        Constant.messages.getString(MESSAGE_PREFIX + "wildcard.name"),
                        "4",
                        param,
                        evidence,
                        Alert.RISK_MEDIUM)
                .setOtherInfo(otherinfo);
    }

    private AlertBuilder buildScriptUnsafeInlineAlert(
            String param, String evidence, String multiPolicyInfo) {
        return getBuilder(
                        Constant.messages.getString(MESSAGE_PREFIX + "scriptsrc.unsafe.name"),
                        "5",
                        param,
                        evidence,
                        Alert.RISK_MEDIUM)
                .setOtherInfo(
                        appendMultiPolicyInfo(
                                Constant.messages.getString(
                                        MESSAGE_PREFIX + "scriptsrc.unsafe.otherinfo"),
                                multiPolicyInfo));
    }

    private AlertBuilder buildStyleUnsafeInlineAlert(
            String param, String evidence, String multiPolicyInfo) {
        return getBuilder(
                        Constant.messages.getString(MESSAGE_PREFIX + "stylesrc.unsafe.name"),
                        "6",
                        param,
                        evidence,
                        Alert.RISK_MEDIUM)
                .setOtherInfo(
                        appendMultiPolicyInfo(
                                Constant.messages.getString(
                                        MESSAGE_PREFIX + "stylesrc.unsafe.otherinfo"),
                                multiPolicyInfo));
    }

    private AlertBuilder buildScriptUnsafeHashAlert(
            String param, String evidence, String multiPolicyInfo) {
        return getBuilder(
                        Constant.messages.getString(
                                MESSAGE_PREFIX + "scriptsrc.unsafe.hashes.name"),
                        "7",
                        param,
                        evidence,
                        Alert.RISK_MEDIUM)
                .setOtherInfo(
                        appendMultiPolicyInfo(
                                Constant.messages.getString(
                                        MESSAGE_PREFIX + "scriptsrc.unsafe.hashes.otherinfo"),
                                multiPolicyInfo))
                .setReference(
                        Constant.messages.getString(
                                MESSAGE_PREFIX + "scriptsrc.unsafe.hashes.refs"));
    }

    private AlertBuilder buildStyleUnsafeHashAlert(
            String param, String evidence, String multiPolicyInfo) {
        return getBuilder(
                        Constant.messages.getString(MESSAGE_PREFIX + "stylesrc.unsafe.hashes.name"),
                        "8",
                        param,
                        evidence,
                        Alert.RISK_MEDIUM)
                .setOtherInfo(
                        appendMultiPolicyInfo(
                                Constant.messages.getString(
                                        MESSAGE_PREFIX + "stylesrc.unsafe.hashes.otherinfo"),
                                multiPolicyInfo))
                .setReference(
                        Constant.messages.getString(
                                MESSAGE_PREFIX + "stylesrc.unsafe.hashes.refs"));
    }

    private AlertBuilder buildMalformedAlert(String param, String evidence, String badChars) {
        return getBuilder(
                        Constant.messages.getString(MESSAGE_PREFIX + "malformed.name"),
                        "9",
                        param,
                        evidence,
                        Alert.RISK_MEDIUM)
                .setOtherInfo(
                        Constant.messages.getString(
                                MESSAGE_PREFIX + "malformed.otherinfo", badChars));
    }

    private AlertBuilder buildScriptUnsafeEvalAlert(
            String param, String evidence, String multiPolicyInfo) {
        return getBuilder(
                        Constant.messages.getString(MESSAGE_PREFIX + "scriptsrc.unsafe.eval.name"),
                        "10",
                        param,
                        evidence,
                        Alert.RISK_MEDIUM)
                .setOtherInfo(
                        appendMultiPolicyInfo(
                                Constant.messages.getString(
                                        MESSAGE_PREFIX + "scriptsrc.unsafe.eval.otherinfo"),
                                multiPolicyInfo));
    }

    private AlertBuilder buildBadMetaAlert(String param, String evidence) {
        return getBuilder(
                        Constant.messages.getString(MESSAGE_PREFIX + "meta.bad.directive.name"),
                        "11",
                        param,
                        evidence,
                        Alert.RISK_MEDIUM)
                .setDescription(
                        Constant.messages.getString(MESSAGE_PREFIX + "meta.bad.directive.desc"));
    }

    // Alert ref 10055-12 ("Header & Meta") is retired/deprecated and should not be reused.

    private AlertBuilder buildNofallbackAlert(
            String param, String evidence, List<String> directives, String multiPolicyInfo) {
        return getBuilder(
                        Constant.messages.getString(MESSAGE_PREFIX + "nofallback.name"),
                        "13",
                        param,
                        evidence,
                        Alert.RISK_MEDIUM)
                .setDescription(Constant.messages.getString(MESSAGE_PREFIX + "nofallback.desc"))
                .setOtherInfo(
                        appendMultiPolicyInfo(
                                Constant.messages.getString(
                                        MESSAGE_PREFIX + "nofallback.otherinfo",
                                        String.join(", ", directives)),
                                multiPolicyInfo));
    }

    @Override
    public List<Alert> getExampleAlerts() {
        List<Alert> alerts = new ArrayList<>();
        alerts.add(
                getBuilder(
                                Constant.messages.getString(MESSAGE_PREFIX + "xcsp.name"),
                                "1",
                                HTTP_HEADER_XCSP,
                                "default-src 'self'",
                                Alert.RISK_LOW)
                        .setOtherInfo(
                                Constant.messages.getString(MESSAGE_PREFIX + "xcsp.otherinfo"))
                        .build());
        alerts.add(
                getBuilder(
                                Constant.messages.getString(MESSAGE_PREFIX + "xwkcsp.name"),
                                "2",
                                HTTP_HEADER_WEBKIT_CSP,
                                "default-src 'self'",
                                Alert.RISK_LOW)
                        .setOtherInfo(
                                Constant.messages.getString(MESSAGE_PREFIX + "xwkcsp.otherinfo"))
                        .build());
        alerts.add(
                getBuilder(
                                Constant.messages.getString(MESSAGE_PREFIX + "notices.name"),
                                "3",
                                HttpFieldsNames.CONTENT_SECURITY_POLICY,
                                "default-src none; report-to csp-endpoint ",
                                Alert.RISK_LOW)
                        .setOtherInfo(
                                "Warnings:\\nThis host name is unusual, and likely meant to be a keyword that is missing the required quotes: 'none'.")
                        .build());
        alerts.add(
                buildWildcardAlert(
                                HttpFieldsNames.CONTENT_SECURITY_POLICY,
                                "connect-src *; default-src 'self'; form-action 'none'; frame-ancestors 'self'",
                                Constant.messages.getString(
                                        MESSAGE_PREFIX + "wildcard.otherinfo", "connect-src"))
                        .build());
        alerts.add(
                buildScriptUnsafeInlineAlert(
                                HttpFieldsNames.CONTENT_SECURITY_POLICY,
                                "script-src 'unsafe-inline'",
                                "")
                        .build());
        alerts.add(
                buildStyleUnsafeInlineAlert(
                                HttpFieldsNames.CONTENT_SECURITY_POLICY,
                                "style-src 'unsafe-inline'",
                                "")
                        .build());
        alerts.add(
                buildScriptUnsafeHashAlert(
                                HttpFieldsNames.CONTENT_SECURITY_POLICY,
                                "default-src 'self'; script-src 'unsafe-hashes' 'sha256-jzgBGA4UWFFmpOBq0JpdsySukE1FrEN5bUpoK8Z29fY='",
                                "")
                        .build());
        alerts.add(
                buildStyleUnsafeHashAlert(
                                HttpFieldsNames.CONTENT_SECURITY_POLICY,
                                "default-src 'self'; style-src 'unsafe-hashes' 'sha256-xyz4zkCjuC3lZcD2UmnqDG0vurmq12W/XKM5Vd0+MlQ='",
                                "")
                        .build());
        alerts.add(
                buildMalformedAlert(
                                HttpFieldsNames.CONTENT_SECURITY_POLICY,
                                "\"default-src ‘self’ 'unsafe-eval' 'unsafe-inline' www.example.net;\"",
                                "‘’")
                        .build());
        alerts.add(
                buildScriptUnsafeEvalAlert(
                                HttpFieldsNames.CONTENT_SECURITY_POLICY,
                                "default-src 'self'; script-src 'unsafe-eval'",
                                "")
                        .build());
        alerts.add(
                buildBadMetaAlert(
                                HttpFieldsNames.CONTENT_SECURITY_POLICY,
                                "default-src 'self'; script-src 'self' "
                                        + "storage.googleapis.com cdn.temasys.io cdn.tiny.cloud *.google-analytics.com; "
                                        + "style-src 'self' *.googleapis.com; font-src 'self' data: *.googleapis.com "
                                        + "fonts.gstatic.com; frame-ancestors 'none'; worker-src 'self'; form-action 'none'")
                        .build());
        alerts.add(
                buildNofallbackAlert(
                                HttpFieldsNames.CONTENT_SECURITY_POLICY,
                                "connect-src *; default-src 'self'; form-action 'none'",
                                List.of(FRAME_ANCESTORS),
                                "")
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
