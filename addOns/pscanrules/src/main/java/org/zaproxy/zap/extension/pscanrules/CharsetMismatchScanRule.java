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

import java.util.List;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import net.htmlparser.jericho.StartTag;
import net.htmlparser.jericho.StartTagType;
import org.apache.commons.lang.StringUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * A port from a Watcher passive scanner (http://websecuritytool.codeplex.com/) rule {@code
 * CasabaSecurity.Web.Watcher.Checks.CheckPasvCharsetMismatch}
 */
public class CharsetMismatchScanRule extends PluginPassiveScanner {

    /** Prefix for internationalized messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanrules.charsetmismatch.";

    private static enum MismatchType {
        NO_MISMATCH_METACONTENTTYPE_MISSING,
        HEADER_METACONTENTYPE_MISMATCH,
        HEADER_METACHARSET_MISMATCH,
        METACONTENTTYPE_METACHARSET_MISMATCH,
        XML_MISMATCH
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    public String getVariant(MismatchType currentType) {
        switch (currentType) {
            case NO_MISMATCH_METACONTENTTYPE_MISSING: // no_mismatch_metacontenttype_missing
                return Constant.messages.getString(
                        MESSAGE_PREFIX + "variant.no_mismatch_metacontenttype_missing");
            case HEADER_METACONTENTYPE_MISMATCH: // header_metacontentype_mismatch
                return Constant.messages.getString(
                        MESSAGE_PREFIX + "variant.header_metacontentype_mismatch");
            case HEADER_METACHARSET_MISMATCH: // header_metacharset_mismatch
                return Constant.messages.getString(
                        MESSAGE_PREFIX + "variant.header_metacharset_mismatch");
            case METACONTENTTYPE_METACHARSET_MISMATCH: // metacontenttype_metacharset_mismatch
                return Constant.messages.getString(
                        MESSAGE_PREFIX + "variant.metacontenttype_metacharset_mismatch");
            case XML_MISMATCH:
            default:
                return "";
        }
    }

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        // do nothing
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
                        raiseAlert(
                                msg,
                                id,
                                metaCharset,
                                bodyContentCharset,
                                MismatchType
                                        .METACONTENTTYPE_METACHARSET_MISMATCH); // body declarations
                        // inconsistent with
                        // each other
                    }
                }
                if (hasBodyCharset) {
                    // Check the body content type charset declaration against the header
                    if (!bodyContentCharset.equalsIgnoreCase(headerCharset)) {
                        raiseAlert(
                                msg,
                                id,
                                headerCharset,
                                bodyContentCharset,
                                MismatchType.HEADER_METACONTENTYPE_MISMATCH); // body declaration
                        // doesn't match header
                    }
                }
                if (hasMetaCharset) {
                    // Check the body meta charset declaration against the header
                    if (!metaCharset.equalsIgnoreCase(headerCharset)) {
                        raiseAlert(
                                msg,
                                id,
                                headerCharset,
                                metaCharset,
                                MismatchType
                                        .HEADER_METACHARSET_MISMATCH); // body declaration doesn't
                        // match header
                    }
                    // If Threshold is LOW be picky and report that
                    // only a meta charset declaration might be insufficient coverage for older
                    // clients
                    if (AlertThreshold.LOW.equals(pluginThreshold) && hasBodyCharset == false) {
                        raiseAlert(
                                msg,
                                id,
                                "",
                                "",
                                MismatchType
                                        .NO_MISMATCH_METACONTENTTYPE_MISSING); // body declaration
                        // does match header
                        // but may overlook
                        // older clients
                    }
                }
            }
        } else if (isResponseXML(msg, source)) { // Check XML response charset
            // We're interested in the 'encoding' attribute defined in the XML
            // declaration tag (<?xml enconding=".."?>
            //
            // TODO: could there be more than one XML declaration tag for a single XML file?
            List<StartTag> xmlDeclarationTags =
                    source.getAllStartTags(StartTagType.XML_DECLARATION);
            if (xmlDeclarationTags.size() > 0) {
                StartTag xmlDeclarationTag = xmlDeclarationTags.get(0);
                String encoding = xmlDeclarationTag.getAttributeValue("encoding");
                if (!headerCharset.equalsIgnoreCase(encoding)) {
                    raiseAlert(msg, id, headerCharset, encoding, MismatchType.XML_MISMATCH);
                }
            }
        }
    }

    // TODO: Fix up to support other variations of text/html.
    // FIX: This will match Atom and RSS feeds now, which set text/html but
    // use &lt;?xml&gt; in content

    private boolean isResponseHTML(HttpMessage message, Source source) {
        String contentType = message.getResponseHeader().getHeader(HttpHeader.CONTENT_TYPE);
        if (contentType == null) {
            return false;
        }

        return contentType.indexOf("text/html") != -1
                || contentType.indexOf("application/xhtml+xml") != -1
                || contentType.indexOf("application/xhtml") != -1;
    }

    private boolean isResponseXML(HttpMessage message, Source source) {
        // Return true if source or response is identified as XML
        return source.isXML() || message.getResponseHeader().isXml();
    }

    private String getBodyContentCharset(String bodyContentType) {
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

    private void raiseAlert(
            HttpMessage msg,
            int id,
            String firstCharset,
            String secondCharset,
            MismatchType currentMismatch) {
        newAlert()
                .setName(
                        getName()
                                + " "
                                + getVariant(
                                        currentMismatch)) // Compound name (to account for variant
                // designations, and muitiple alerts on single URI)
                .setRisk(Alert.RISK_INFO)
                .setConfidence(Alert.CONFIDENCE_LOW)
                .setDescription(getDescriptionMessage())
                .setOtherInfo(getExtraInfo(firstCharset, secondCharset, currentMismatch))
                .setSolution(getSolutionMessage())
                .setReference(getReferenceMessage())
                .setCweId(16) // CWE-16: Configuration
                .setWascId(15) // WASC-15: Application Misconfiguration
                .raise();
    }

    @Override
    public int getPluginId() {
        return 90011;
    }

    @Override
    public void setParent(PassiveScanThread parent) {
        // Nothing to do.
    }

    /*
     * Rule-associated messages
     */

    private String getDescriptionMessage() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    private String getSolutionMessage() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    private String getReferenceMessage() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    private String getExtraInfo(
            String firstCharset, String secondCharset, MismatchType mismatchType) {

        String extraInfo = "";

        switch (mismatchType) {
            case NO_MISMATCH_METACONTENTTYPE_MISSING: // no_mismatch_metacontenttype_missing
                extraInfo =
                        Constant.messages.getString(
                                MESSAGE_PREFIX
                                        + "extrainfo.html.no_mismatch_metacontenttype_missing");
                break;
            case HEADER_METACONTENTYPE_MISMATCH: // header_metacontentype_mismatch
                extraInfo =
                        Constant.messages.getString(
                                MESSAGE_PREFIX + "extrainfo.html.header_metacontentype_mismatch",
                                firstCharset,
                                secondCharset);
                break;
            case HEADER_METACHARSET_MISMATCH: // header_metacharset_mismatch
                extraInfo =
                        Constant.messages.getString(
                                MESSAGE_PREFIX + "extrainfo.html.header_metacharset_mismatch",
                                firstCharset,
                                secondCharset);
                break;
            case METACONTENTTYPE_METACHARSET_MISMATCH: // metacontenttype_metacharset_mismatch
                extraInfo =
                        Constant.messages.getString(
                                MESSAGE_PREFIX
                                        + "extrainfo.html.metacontenttype_metacharset_mismatch",
                                firstCharset,
                                secondCharset);
                break;
            case XML_MISMATCH:
                extraInfo =
                        Constant.messages.getString(
                                MESSAGE_PREFIX + "extrainfo.xml", firstCharset, secondCharset);
                break;
        }
        return extraInfo;
    }
}
