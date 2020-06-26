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
package org.zaproxy.zap.extension.pscanrulesBeta;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import org.apache.commons.httpclient.URI;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * Strict-Transport-Security Header Not Set passive scan rule
 * https://github.com/zaproxy/zaproxy/issues/1169
 *
 * @author kingthorin+owaspzap@gmail.com
 */
public class StrictTransportSecurityScanRule extends PluginPassiveScanner {

    private static final String MESSAGE_PREFIX = "pscanbeta.stricttransportsecurity.";
    private static final int PLUGIN_ID = 10035;
    private static final String STS_HEADER = "Strict-Transport-Security";

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
        HSTS_MISSING,
        HSTS_MAX_AGE_DISABLED,
        HSTS_MULTIPLE_HEADERS,
        HSTS_ON_PLAIN_RESP,
        HSTS_MAX_AGE_MISSING,
        HSTS_META,
        HSTS_MALFORMED_MAX_AGE,
        HSTS_MALFORMED_CONTENT
    }

    private static final Logger logger = Logger.getLogger(StrictTransportSecurityScanRule.class);

    @Override
    public void setParent(PassiveScanThread parent) {
        // Nothing to do.
    }

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        // Only checking the response for this plugin
    }

    private void raiseAlert(VulnType currentVT, String evidence, HttpMessage msg, int id) {
        newAlert()
                .setName(getAlertElement(currentVT, "name"))
                .setRisk(getRisk(currentVT))
                .setConfidence(Alert.CONFIDENCE_HIGH)
                .setDescription(getAlertElement(currentVT, "desc"))
                .setSolution(getAlertElement(currentVT, "soln"))
                .setReference(getAlertElement(currentVT, "refs"))
                .setEvidence(evidence)
                .setCweId(16) // CWE-16: Configuration
                .setWascId(15) // WASC-15: Application Misconfiguration
                .raise();
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
                    raiseAlert(VulnType.HSTS_MISSING, null, msg, id);
                }
            } else if (stsOption.size() > 1) { // More than one header found
                raiseAlert(VulnType.HSTS_MULTIPLE_HEADERS, null, msg, id);
            } else { // Single HSTS header entry
                String stsOptionString = stsOption.get(0);
                Matcher badAgeMatcher = BAD_MAX_AGE_PATT.matcher(stsOptionString);
                Matcher maxAgeMatcher = MAX_AGE_PATT.matcher(stsOptionString);
                Matcher malformedMaxAgeMatcher = MALFORMED_MAX_AGE.matcher(stsOptionString);
                Matcher wellformedMatcher = WELL_FORMED_PATT.matcher(stsOptionString);
                if (!wellformedMatcher.matches()) {
                    // Well formed pattern didn't match (perhaps curly quotes or some other unwanted
                    // character(s))
                    raiseAlert(VulnType.HSTS_MALFORMED_CONTENT, STS_HEADER, msg, id);
                } else if (badAgeMatcher.find()) {
                    // Matched BAD_MAX_AGE_PATT, max-age is zero
                    raiseAlert(VulnType.HSTS_MAX_AGE_DISABLED, badAgeMatcher.group(), msg, id);
                } else if (!maxAgeMatcher.find()) {
                    // Didn't find a digit value associated with max-age
                    raiseAlert(VulnType.HSTS_MAX_AGE_MISSING, stsOption.get(0), msg, id);
                } else if (malformedMaxAgeMatcher.find()) {
                    // Found max-age but it was malformed
                    raiseAlert(VulnType.HSTS_MALFORMED_MAX_AGE, stsOption.get(0), msg, id);
                }
            }
        } else if (AlertThreshold.LOW.equals(this.getAlertThreshold()) && !stsOption.isEmpty()) {
            // isSecure is false at this point
            // HSTS Header found on non-HTTPS response (technically there could be more than one
            // but we only care that there is one or more)
            raiseAlert(VulnType.HSTS_ON_PLAIN_RESP, stsOption.get(0), msg, id);
        }

        if (metaHSTS != null) {
            // HSTS found defined by META tag
            raiseAlert(VulnType.HSTS_META, metaHSTS, msg, id);
        }

        if (logger.isDebugEnabled()) {
            logger.debug(
                    "\tScan of record "
                            + id
                            + " took "
                            + (System.currentTimeMillis() - start)
                            + " ms");
        }
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "rule.name");
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
}
