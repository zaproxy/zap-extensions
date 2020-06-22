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

import com.shapesecurity.salvation.ParserWithLocation;
import com.shapesecurity.salvation.data.Notice;
import com.shapesecurity.salvation.data.Origin;
import com.shapesecurity.salvation.data.Policy;
import com.shapesecurity.salvation.data.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import net.htmlparser.jericho.Source;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
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
    private static final Logger LOGGER = Logger.getLogger(ContentSecurityPolicyScanRule.class);

    private static final String HTTP_HEADER_CSP = "Content-Security-Policy";
    private static final String HTTP_HEADER_XCSP = "X-Content-Security-Policy";
    private static final String HTTP_HEADER_WEBKIT_CSP = "X-WebKit-CSP";

    private static final String WILDCARD_URI = "http://*";
    private static final URI PARSED_WILDCARD_URI = URI.parse(WILDCARD_URI);

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

    @Override
    public void setParent(PassiveScanThread parent) {
        // Nothing to do.
    }

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        // Only checking the response for this plugin
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        boolean cspHeaderFound = false;
        int noticesRisk = Alert.RISK_INFO;
        // LOGGER.setLevel(Level.DEBUG); //Enable for debugging

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Start " + id + " : " + msg.getRequestHeader().getURI().toString());
        }

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

        // X-Content-Security-Policy is an older header, supported by Firefox
        // 4.0+, and IE 10+ (in a limited fashion)
        List<String> xcspOptions = msg.getResponseHeader().getHeaderValues(HTTP_HEADER_XCSP);
        if (!xcspOptions.isEmpty()) {
            raiseAlert(
                    msg,
                    Constant.messages.getString(MESSAGE_PREFIX + "xcsp.name"),
                    id,
                    Constant.messages.getString(MESSAGE_PREFIX + "xcsp.desc"),
                    getHeaderField(msg, HTTP_HEADER_XCSP).get(0),
                    cspHeaderFound ? Alert.RISK_INFO : Alert.RISK_LOW,
                    xcspOptions.get(0),
                    false,
                    "");
        }

        // X-WebKit-CSP is supported by Chrome 14+, and Safari 6+
        List<String> xwkcspOptions =
                msg.getResponseHeader().getHeaderValues(HTTP_HEADER_WEBKIT_CSP);
        if (!xwkcspOptions.isEmpty()) {
            raiseAlert(
                    msg,
                    Constant.messages.getString(MESSAGE_PREFIX + "xwkcsp.name"),
                    id,
                    Constant.messages.getString(MESSAGE_PREFIX + "xwkcsp.desc"),
                    getHeaderField(msg, HTTP_HEADER_WEBKIT_CSP).get(0),
                    cspHeaderFound ? Alert.RISK_INFO : Alert.RISK_LOW,
                    xwkcspOptions.get(0),
                    false,
                    "");
        }

        if (cspHeaderFound) {
            ArrayList<Notice> notices = new ArrayList<>();
            Origin origin = URI.parse(msg.getRequestHeader().getURI().toString());
            Policy unifiedPolicy = new Policy(origin);
            boolean multipleCsp = cspOptions.size() > 1;
            if (multipleCsp) {
                for (String csp : cspOptions) {
                    Policy policy = ParserWithLocation.parse(csp, origin);
                    unifiedPolicy.intersect(policy);
                }
            }
            String unifiedPolicyText = multipleCsp ? unifiedPolicy.show() : cspOptions.get(0);
            Policy pol =
                    ParserWithLocation.parse(
                            unifiedPolicyText, origin, notices); // Populate notices

            if (!notices.isEmpty()) {
                String cspNoticesString = getCSPNoticesString(notices);
                if (cspNoticesString.contains(
                                Constant.messages.getString(MESSAGE_PREFIX + "notices.errors"))
                        || cspNoticesString.contains(
                                Constant.messages.getString(MESSAGE_PREFIX + "notices.warnings"))) {
                    noticesRisk = Alert.RISK_LOW;
                } else {
                    noticesRisk = Alert.RISK_INFO;
                }
                raiseAlert(
                        msg,
                        Constant.messages.getString(MESSAGE_PREFIX + "notices.name"),
                        id,
                        cspNoticesString,
                        getHeaderField(msg, HTTP_HEADER_CSP).get(0),
                        noticesRisk,
                        cspOptions.get(0),
                        multipleCsp,
                        unifiedPolicyText);
            }

            List<String> allowedWildcardSources =
                    getAllowedWildcardSources(unifiedPolicyText, origin);
            if (!allowedWildcardSources.isEmpty()) {
                List<String> allowedDirectivesWithoutFallback =
                        allowedWildcardSources.stream()
                                .distinct()
                                .filter(DIRECTIVES_WITHOUT_FALLBACK::contains)
                                .collect(Collectors.toList());
                String allowedWildcardSrcs = String.join(", ", allowedWildcardSources);
                String wildcardSrcDesc =
                        Constant.messages.getString(
                                MESSAGE_PREFIX + "wildcard.desc", allowedWildcardSrcs);
                if (!allowedDirectivesWithoutFallback.isEmpty()) {
                    wildcardSrcDesc +=
                            Constant.messages.getString(
                                    "pscanrules.csp.desc.extended",
                                    String.join(", ", allowedDirectivesWithoutFallback));
                }
                raiseAlert(
                        msg,
                        Constant.messages.getString(MESSAGE_PREFIX + "wildcard.name"),
                        id,
                        wildcardSrcDesc,
                        getHeaderField(msg, HTTP_HEADER_CSP).get(0),
                        Alert.RISK_MEDIUM,
                        cspOptions.get(0),
                        multipleCsp,
                        unifiedPolicyText);
            }

            if (pol.allowsUnsafeInlineScript()) {
                raiseAlert(
                        msg,
                        Constant.messages.getString(MESSAGE_PREFIX + "scriptsrc.unsafe.name"),
                        id,
                        Constant.messages.getString(MESSAGE_PREFIX + "scriptsrc.unsafe.desc"),
                        getHeaderField(msg, HTTP_HEADER_CSP).get(0),
                        Alert.RISK_MEDIUM,
                        cspOptions.get(0),
                        multipleCsp,
                        unifiedPolicyText);
            }

            if (pol.allowsUnsafeInlineStyle()) {
                raiseAlert(
                        msg,
                        Constant.messages.getString(MESSAGE_PREFIX + "stylesrc.unsafe.name"),
                        id,
                        Constant.messages.getString(MESSAGE_PREFIX + "stylesrc.unsafe.desc"),
                        getHeaderField(msg, HTTP_HEADER_CSP).get(0),
                        Alert.RISK_MEDIUM,
                        cspOptions.get(0),
                        multipleCsp,
                        unifiedPolicyText);
            }
        }

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(
                    "\tScan of record "
                            + String.valueOf(id)
                            + " took "
                            + (System.currentTimeMillis() - start)
                            + " ms");
        }
    }

    private String getCSPNoticesString(ArrayList<Notice> notices) {
        char NEWLINE = '\n';
        StringBuilder returnSb = new StringBuilder();

        ArrayList<Notice> errorsList = Notice.getAllErrors(notices);
        if (!errorsList.isEmpty()) {
            returnSb.append(Constant.messages.getString(MESSAGE_PREFIX + "notices.errors"))
                    .append(NEWLINE);
            for (Notice notice : errorsList) {
                returnSb.append(notice.show()).append(NEWLINE);
                // Ex: 1:1: Unrecognised directive-name: "image-src".
            }
        }

        ArrayList<Notice> warnList = Notice.getAllWarnings(notices);
        if (!warnList.isEmpty()) {
            returnSb.append(Constant.messages.getString(MESSAGE_PREFIX + "notices.warnings"))
                    .append(NEWLINE);
            for (Notice notice : warnList) {
                returnSb.append(notice.show()).append(NEWLINE);
                // Ex: 1:25: This host name is unusual, and likely meant to be a
                // keyword that is missing the required quotes: 'none'.
            }
        }

        ArrayList<Notice> infoList = Notice.getAllInfos(notices);
        if (!infoList.isEmpty()) {
            returnSb.append(Constant.messages.getString(MESSAGE_PREFIX + "notices.infoitems"))
                    .append(NEWLINE);
            for (Notice notice : infoList) {
                returnSb.append(notice.show()).append(NEWLINE);
                // Ex: 1:31: A draft of the next version of CSP deprecates
                // report-uri in favour of a new report-to directive.
            }
        }
        return returnSb.toString();
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

    private List<String> getAllowedWildcardSources(String policyText, Origin origin) {

        List<String> allowedSources = new ArrayList<String>();
        Policy pol = ParserWithLocation.parse(policyText, origin);

        if (pol.allowsScriptFromSource(PARSED_WILDCARD_URI)) {
            allowedSources.add("script-src");
            allowedSources.add("script-src-elem");
            allowedSources.add("script-src-attr");
        }
        if (pol.allowsStyleFromSource(PARSED_WILDCARD_URI)) {
            allowedSources.add("style-src");
            allowedSources.add("style-src-elem");
            allowedSources.add("style-src-attr");
        }
        if (pol.allowsImgFromSource(PARSED_WILDCARD_URI)) {
            allowedSources.add("img-src");
        }
        if (pol.allowsConnectTo(PARSED_WILDCARD_URI)) {
            allowedSources.add("connect-src");
        }
        if (pol.allowsFrameFromSource(PARSED_WILDCARD_URI)) {
            allowedSources.add("frame-src");
        }
        if (pol.allowsFrameAncestor(PARSED_WILDCARD_URI)) {
            allowedSources.add("frame-ancestors");
        }
        if (pol.allowsFontFromSource(PARSED_WILDCARD_URI)) {
            allowedSources.add("font-src");
        }
        if (pol.allowsMediaFromSource(PARSED_WILDCARD_URI)) {
            allowedSources.add("media-src");
        }
        if (pol.allowsObjectFromSource(PARSED_WILDCARD_URI)) {
            allowedSources.add("object-src");
        }
        if (pol.allowsManifestFromSource(PARSED_WILDCARD_URI)) {
            allowedSources.add("manifest-src");
        }
        if (pol.allowsWorkerFromSource(PARSED_WILDCARD_URI)) {
            allowedSources.add("worker-src");
        }
        if (pol.allowsPrefetchFromSource(PARSED_WILDCARD_URI)) {
            allowedSources.add("prefetch-src");
        }
        if (pol.allowsFormAction(PARSED_WILDCARD_URI)) {
            allowedSources.add("form-action");
        }
        return allowedSources;
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    private String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    private String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    private void raiseAlert(
            HttpMessage msg,
            String name,
            int id,
            String description,
            String param,
            int risk,
            String evidence,
            boolean multipleCsp,
            String policy) {
        String alertName = StringUtils.isEmpty(name) ? getName() : getName() + ": " + name;
        String otherInfo =
                multipleCsp
                        ? Constant.messages.getString(MESSAGE_PREFIX + "otherinfo", policy)
                        : "";

        newAlert()
                .setName(alertName)
                .setRisk(risk)
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setDescription(description)
                .setParam(param)
                .setOtherInfo(otherInfo)
                .setSolution(getSolution())
                .setReference(getReference())
                .setEvidence(evidence)
                .setCweId(16) // CWE-16: Configuration
                .setWascId(15) // WASC-15: Application Misconfiguration)
                .raise();
    }
}
