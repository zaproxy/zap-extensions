/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
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

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import net.htmlparser.jericho.StartTag;
import net.htmlparser.jericho.StartTagType;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * A port from a Watcher passive scanner (http://websecuritytool.codeplex.com/) rule {@code
 * CasabaSecurity.Web.Watcher.Checks.CheckPasvCharsetMismatch}
 */
public class CharsetMismatchScanRule extends PluginPassiveScanner
        implements CommonPassiveScanRuleInfo {

    /** Prefix for internationalized messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanrules.charsetmismatch.";

    private static final int PLUGIN_ID = 90011;

    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(CommonAlertTag.toMap(CommonAlertTag.SYSTEMIC));
        alertTags.put(PolicyTag.PENTEST.getTag(), "");
        alertTags.put(PolicyTag.QA_STD.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    private enum MismatchType {
        HEADER_METACONTENTYPE_MISMATCH(
                "-1",
                "name.header_metacontentype_mismatch",
                "extrainfo.html.header_metacontentype_mismatch"),
        HEADER_METACHARSET_MISMATCH(
                "-2",
                "name.header_metacharset_mismatch",
                "extrainfo.html.header_metacharset_mismatch"),
        METACONTENTTYPE_METACHARSET_MISMATCH(
                "-3",
                "name.metacontenttype_metacharset_mismatch",
                "extrainfo.html.metacontenttype_metacharset_mismatch"),
        XML_MISMATCH("-4", "name", "extrainfo.xml");

        private final String alertRef;
        private final String name;
        private final String otherInfoKey;

        MismatchType(String ref, String nameKey, String otherInfoKey) {
            this.alertRef = PLUGIN_ID + ref;
            this.name = Constant.messages.getString(MESSAGE_PREFIX + nameKey);
            this.otherInfoKey = MESSAGE_PREFIX + otherInfoKey;
        }

        String getAlertRef() {
            return this.alertRef;
        }

        String getName() {
            return this.name;
        }

        private String getExtraInfo(String firstCharset, String secondCharset) {
            return Constant.messages.getString(otherInfoKey, firstCharset, secondCharset);
        }
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        if (msg.getResponseBody().length() == 0) {
            return;
        }

        // Charset specified in the Content-Type header
        String headerCharset = msg.getResponseHeader().getCharset();

        // TODO: If Content-Type in the Header doesn't specify a charset, or
        // the Content-Type header is missing - should we raise some different
        // alert? Ignore such case for now.
        if (headerCharset == null) {
            return; // No header == No alert
        }
        headerCharset = headerCharset.trim();

        if (isResponseHTML(msg, source)) { // Check HTML response charset
            // Looking for:
            //     <META http-equiv="Content-Type" content="text/html; charset=EUC-JP">
            //     <META charset="utf-8">
            // TODO: could there be more than single "Content-Type" meta per HTML?

            String bodyContentCharset = "";
            String metaCharset = "";

            List<Element> metaElements = source.getAllElements(HTMLElementName.META);

            if (metaElements != null) {
                for (Element metaElement : metaElements) {
                    // Ref: http://www.w3.org/TR/html401/charset.html#h-5.2.2
                    String httpEquiv = metaElement.getAttributeValue("http-equiv");
                    String bodyContentType = metaElement.getAttributeValue("content");
                    // Ref: http://www.w3.org/TR/html5/document-metadata.html#charset
                    if (StringUtils.isBlank(metaCharset)) {
                        metaCharset = metaElement.getAttributeValue("charset");
                    }

                    // If META element defines HTTP-EQUIV and CONTENT attributes,
                    // or META element defines charset
                    // get charset values
                    if (httpEquiv != null
                            && bodyContentType != null
                            && httpEquiv.equalsIgnoreCase("content-type")) {
                        bodyContentCharset = getBodyContentCharset(bodyContentType);
                    }
                }
                boolean hasBodyCharset = true;
                boolean hasMetaCharset = true;
                // Plugin Threshold as defined in by the user via policy/settings
                AlertThreshold pluginThreshold = this.getAlertThreshold();

                if (bodyContentCharset == null || bodyContentCharset.isEmpty()) {
                    hasBodyCharset = false; // Got http-equiv and content but no charset
                }
                if (metaCharset == null || metaCharset.isEmpty()) {
                    hasMetaCharset = false;
                }

                if (hasBodyCharset && hasMetaCharset) {
                    // If Threshold is LOW be picky and check the two body declarations against each
                    // other
                    if (AlertThreshold.LOW.equals(pluginThreshold)
                            && !bodyContentCharset.equalsIgnoreCase(metaCharset)) {
                        buildAlert(
                                        metaCharset,
                                        bodyContentCharset,
                                        MismatchType.METACONTENTTYPE_METACHARSET_MISMATCH)
                                .raise();
                    }
                }
                if (hasBodyCharset) {
                    // Check the body content type charset declaration against the header
                    if (!bodyContentCharset.equalsIgnoreCase(headerCharset)) {
                        buildAlert(
                                        headerCharset,
                                        bodyContentCharset,
                                        MismatchType.HEADER_METACONTENTYPE_MISMATCH)
                                .raise();
                    }
                }
                if (hasMetaCharset) {
                    // Check the body meta charset declaration against the header
                    if (!metaCharset.equalsIgnoreCase(headerCharset)) {
                        buildAlert(
                                        headerCharset,
                                        metaCharset,
                                        MismatchType.HEADER_METACHARSET_MISMATCH)
                                .raise();
                    }
                }
            }
        } else if (isResponseXML(msg, source)) { // Check XML response charset
            // We're interested in the 'encoding' attribute defined in the XML
            // declaration tag (<?xml encoding=".."?>
            //
            // TODO: could there be more than one XML declaration tag for a single XML file?
            List<StartTag> xmlDeclarationTags =
                    source.getAllStartTags(StartTagType.XML_DECLARATION);
            if (!xmlDeclarationTags.isEmpty()) {
                StartTag xmlDeclarationTag = xmlDeclarationTags.get(0);
                String encoding = xmlDeclarationTag.getAttributeValue("encoding");
                if (!headerCharset.equalsIgnoreCase(encoding)) {
                    buildAlert(headerCharset, encoding, MismatchType.XML_MISMATCH).raise();
                }
            }
        }
    }

    // TODO: Fix up to support other variations of text/html.
    // FIX: This will match Atom and RSS feeds now, which set text/html but
    // use &lt;?xml&gt; in content

    private static boolean isResponseHTML(HttpMessage message, Source source) {
        String contentType = message.getResponseHeader().getHeader(HttpHeader.CONTENT_TYPE);
        if (contentType == null) {
            return false;
        }

        return contentType.indexOf("text/html") != -1
                || contentType.indexOf("application/xhtml+xml") != -1
                || contentType.indexOf("application/xhtml") != -1;
    }

    private static boolean isResponseXML(HttpMessage message, Source source) {
        // Return true if source or response is identified as XML
        return source.isXML() || message.getResponseHeader().isXml();
    }

    private static String getBodyContentCharset(String bodyContentType) {
        // preconditions
        assert bodyContentType != null;

        String charset = null;

        bodyContentType = bodyContentType.trim();

        int charsetIndex;
        if ((charsetIndex = bodyContentType.indexOf("charset=")) != -1) {
            // 8 is a length of "charset="
            charset = bodyContentType.substring(charsetIndex + 8);
        }

        return charset;
    }

    private AlertBuilder buildAlert(
            String firstCharset, String secondCharset, MismatchType currentMismatch) {
        return newAlert()
                .setName(currentMismatch.getName())
                .setRisk(getRisk())
                .setConfidence(Alert.CONFIDENCE_LOW)
                .setDescription(getDescription())
                .setOtherInfo(currentMismatch.getExtraInfo(firstCharset, secondCharset))
                .setSolution(getSolution())
                .setReference(getReference())
                .setCweId(getCweId())
                .setWascId(getWascId())
                .setAlertRef(currentMismatch.getAlertRef());
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    /*
     * Rule-associated messages
     */

    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    public int getRisk() {
        return Alert.RISK_INFO;
    }

    public int getCweId() {
        return 436; // CWE-436: Interpretation Conflict
    }

    public int getWascId() {
        return 15; // WASC-15: Application Misconfiguration
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return Arrays.stream(MismatchType.values())
                .map(
                        mismatchType ->
                                buildAlert(StandardCharsets.UTF_8.name(), "ISO-123", mismatchType)
                                        .build())
                .toList();
    }
}
