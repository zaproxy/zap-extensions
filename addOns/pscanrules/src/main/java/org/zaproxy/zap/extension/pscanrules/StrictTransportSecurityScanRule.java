/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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

import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import org.apache.commons.httpclient.URI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * Strict-Transport-Security Header Not Set passive scan rule
 * https://github.com/zaproxy/zaproxy/issues/1169
 */
public class StrictTransportSecurityScanRule extends PluginPassiveScanner
        implements CommonPassiveScanRuleInfo {

    private static final String MESSAGE_PREFIX = "pscanrules.stricttransportsecurity.";
    private static final int PLUGIN_ID = 10035;
    private static final String STS_HEADER = "Strict-Transport-Security";
    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
                    CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG);

    // max-age=0 disabled HSTS. It's allowed by the spec,
    // and is used to reset browser's settings for HSTS.
    // If found raise an alert.
    // Pattern accounts for potential spaces and quotes
    private static final Pattern BAD_MAX_AGE_PATT =
            Pattern.compile(
                    "\\bmax-age\\s*=\\s*\'*\"*\\s*0\\s*\"*\'*\\s*", Pattern.CASE_INSENSITIVE);
    // Ensure max-age actually contains a digit
    private static final Pattern MAX_AGE_PATT =
            Pattern.compile(
                    "\\bmax-age\\s*=\\s*\'*\"*\\s*\\s*\\d+\\s*\"*\'*\\s*",
                    Pattern.CASE_INSENSITIVE);
    // Ensure quotes aren't before max-age
    private static final Pattern MALFORMED_MAX_AGE =
            Pattern.compile("[\'+|\"+]\\s*max", Pattern.CASE_INSENSITIVE);
    // Ensure printable ascii
    private static final Pattern WELL_FORMED_PATT =
            Pattern.compile("\\p{Print}*", Pattern.CASE_INSENSITIVE);

    private enum VulnType {
        HSTS_MISSING(1),
        HSTS_MAX_AGE_DISABLED(2),
        HSTS_MULTIPLE_HEADERS(3),
        HSTS_ON_PLAIN_RESP(4),
        HSTS_MAX_AGE_MISSING(5),
        HSTS_META(6),
        HSTS_MALFORMED_MAX_AGE(7),
        HSTS_MALFORMED_CONTENT(8);

        private final int ref;

        private VulnType(int ref) {
            this.ref = ref;
        }

        public int getRef() {
            return this.ref;
        }
    }

    private static final Logger LOGGER =
            LogManager.getLogger(StrictTransportSecurityScanRule.class);

    private AlertBuilder buildAlert(VulnType currentVT, String evidence) {
        return newAlert()
                .setName(getAlertElement(currentVT, "name"))
                .setRisk(getRisk(currentVT))
                .setConfidence(Alert.CONFIDENCE_HIGH)
                .setDescription(getAlertElement(currentVT, "desc"))
                .setSolution(getAlertElement(currentVT, "soln"))
                .setReference(getAlertElement(currentVT, "refs"))
                .setEvidence(evidence)
                .setCweId(319) // CWE-319: Cleartext Transmission of Sensitive Information
                .setWascId(15) // WASC-15: Application Misconfiguration
                .setAlertRef(PLUGIN_ID + "-" + currentVT.getRef());
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        long start = System.currentTimeMillis();
        List<String> stsOption = msg.getResponseHeader().getHeaderValues(STS_HEADER);
        String metaHSTS = getMetaHSTSEvidence(source);

        if (msg.getRequestHeader().isSecure()) { // No point reporting missing for non-SSL resources
            // Content available via both HTTPS and HTTP is a separate though related issue
            if (stsOption.isEmpty()) { // Header NOT found
                boolean report = true;
                if (!this.getAlertThreshold().equals(AlertThreshold.LOW)
                        && HttpStatusCode.isRedirection(msg.getResponseHeader().getStatusCode())) {
                    // Only report https redirects to the same domain at low threshold
                    try {
                        String redirStr = msg.getResponseHeader().getHeader(HttpHeader.LOCATION);
                        URI srcUri = msg.getRequestHeader().getURI();
                        URI redirUri = new URI(redirStr, false);
                        if (redirUri.isRelativeURI()
                                || (redirUri.getScheme().equalsIgnoreCase("https")
                                        && redirUri.getHost().equals(srcUri.getHost())
                                        && redirUri.getPort() == srcUri.getPort())) {
                            report = false;
                        }
                    } catch (Exception e) {
                        // Ignore, so report the missing header
                    }
                }
                if (report) {
                    buildAlert(VulnType.HSTS_MISSING, "").raise();
                }
            } else if (stsOption.size() > 1) { // More than one header found
                buildAlert(VulnType.HSTS_MULTIPLE_HEADERS, "").raise();
            } else { // Single HSTS header entry
                String stsOptionString = stsOption.get(0);
                Matcher badAgeMatcher = BAD_MAX_AGE_PATT.matcher(stsOptionString);
                Matcher maxAgeMatcher = MAX_AGE_PATT.matcher(stsOptionString);
                Matcher malformedMaxAgeMatcher = MALFORMED_MAX_AGE.matcher(stsOptionString);
                Matcher wellformedMatcher = WELL_FORMED_PATT.matcher(stsOptionString);
                if (!wellformedMatcher.matches()) {
                    // Well formed pattern didn't match (perhaps curly quotes or some other unwanted
                    // character(s))
                    buildAlert(VulnType.HSTS_MALFORMED_CONTENT, STS_HEADER).raise();
                } else if (badAgeMatcher.find()) {
                    // Matched BAD_MAX_AGE_PATT, max-age is zero
                    buildAlert(VulnType.HSTS_MAX_AGE_DISABLED, badAgeMatcher.group()).raise();
                } else if (!maxAgeMatcher.find()) {
                    // Didn't find a digit value associated with max-age
                    buildAlert(VulnType.HSTS_MAX_AGE_MISSING, stsOption.get(0)).raise();
                } else if (malformedMaxAgeMatcher.find()) {
                    // Found max-age but it was malformed
                    buildAlert(VulnType.HSTS_MALFORMED_MAX_AGE, stsOption.get(0)).raise();
                }
            }
        } else if (AlertThreshold.LOW.equals(this.getAlertThreshold()) && !stsOption.isEmpty()) {
            // isSecure is false at this point
            // HSTS Header found on non-HTTPS response (technically there could be more than one
            // but we only care that there is one or more)
            buildAlert(VulnType.HSTS_ON_PLAIN_RESP, stsOption.get(0)).raise();
        }

        if (metaHSTS != null) {
            // HSTS found defined by META tag
            buildAlert(VulnType.HSTS_META, metaHSTS).raise();
        }

        LOGGER.debug("\tScan of record {} took {}ms", id, System.currentTimeMillis() - start);
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "rule.name");
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    private String getAlertElement(VulnType currentVT, String element) {
        String elementValue = "";
        switch (currentVT) {
            case HSTS_MISSING:
                elementValue = Constant.messages.getString(MESSAGE_PREFIX + element);
                break;
            case HSTS_MAX_AGE_DISABLED:
                elementValue = Constant.messages.getString(MESSAGE_PREFIX + "max.age." + element);
                break;
            case HSTS_MULTIPLE_HEADERS:
                elementValue =
                        Constant.messages.getString(
                                MESSAGE_PREFIX + "compliance.multiple.header." + element);
                break;
            case HSTS_ON_PLAIN_RESP:
                elementValue =
                        Constant.messages.getString(MESSAGE_PREFIX + "plain.resp." + element);
                break;
            case HSTS_MAX_AGE_MISSING:
                elementValue =
                        Constant.messages.getString(
                                MESSAGE_PREFIX + "compliance.max.age.missing." + element);
                break;
            case HSTS_META:
                elementValue =
                        Constant.messages.getString(MESSAGE_PREFIX + "compliance.meta." + element);
                break;
            case HSTS_MALFORMED_MAX_AGE:
                elementValue =
                        Constant.messages.getString(
                                MESSAGE_PREFIX + "compliance.max.age.malformed." + element);
                break;
            case HSTS_MALFORMED_CONTENT:
                elementValue =
                        Constant.messages.getString(
                                MESSAGE_PREFIX + "compliance.malformed.content." + element);
                break;
        }
        return elementValue;
    }

    private int getRisk(VulnType currentVT) {
        switch (currentVT) {
            case HSTS_MISSING:
            case HSTS_MAX_AGE_DISABLED:
            case HSTS_MULTIPLE_HEADERS:
            case HSTS_MAX_AGE_MISSING:
            case HSTS_META:
            case HSTS_MALFORMED_MAX_AGE:
            case HSTS_MALFORMED_CONTENT:
                return Alert.RISK_LOW;
            case HSTS_ON_PLAIN_RESP:
            default:
                return Alert.RISK_INFO;
        }
    }

    /**
     * Checks the source of the response for HSTS being set via a META tag which is explicitly not
     * supported per the spec (rfc6797).
     *
     * @param source the source of the response to be analyzed.
     * @return returns a string if HSTS was set via META (for use as alert evidence) otherwise
     *     return {@code null}.
     * @see <a href="https://tools.ietf.org/html/rfc6797#section-8.5">RFC 6797 Section 8.5</a>
     */
    private String getMetaHSTSEvidence(Source source) {
        List<Element> metaElements = source.getAllElements(HTMLElementName.META);
        String httpEquiv;

        if (metaElements != null) {
            for (Element metaElement : metaElements) {
                httpEquiv = metaElement.getAttributeValue("http-equiv");
                if (STS_HEADER.equalsIgnoreCase(httpEquiv)) {
                    return httpEquiv; // This is a META which attempts to define HSTS return it's
                    // value
                }
            }
        }
        return null;
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(
                buildAlert(VulnType.HSTS_MISSING, "").build(),
                buildAlert(VulnType.HSTS_MAX_AGE_DISABLED, "max-age=0").build(),
                buildAlert(VulnType.HSTS_MULTIPLE_HEADERS, "").build(),
                buildAlert(VulnType.HSTS_ON_PLAIN_RESP, "max-age=86400").build(),
                buildAlert(VulnType.HSTS_MAX_AGE_MISSING, "").build(),
                buildAlert(VulnType.HSTS_META, STS_HEADER).build(),
                buildAlert(VulnType.HSTS_MALFORMED_MAX_AGE, "\"max-age=84600\"").build(),
                buildAlert(VulnType.HSTS_MALFORMED_CONTENT, STS_HEADER).build());
    }
}
