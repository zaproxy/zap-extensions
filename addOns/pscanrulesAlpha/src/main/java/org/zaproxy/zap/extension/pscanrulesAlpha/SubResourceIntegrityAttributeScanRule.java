/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrulesAlpha;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteMap;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.http.domains.RegexTrust;
import org.zaproxy.addon.commonlib.http.domains.TrustedDomains;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.extension.ruleconfig.RuleConfigParam;

/** Detect missing attribute integrity in supported elements */
public class SubResourceIntegrityAttributeScanRule extends PluginPassiveScanner {

    private static final Logger logger =
            LogManager.getLogger(SubResourceIntegrityAttributeScanRule.class);

    private enum SupportedElements {
        // From
        // https://w3c.github.io/webappsec-subresource-integrity/#verification-of-html-document-subresources
        // To support integrity metadata for some of these elements, a new integrity attribute is
        // added
        // to the list of content attributes for the link and script elements.
        // Note: A future revision of this specification is likely to include integrity support for
        // all
        // possible subresources, i.e., a, audio, embed, iframe, img, link, object, script, source,
        // track, and video elements.

        SCRIPT(HTMLElementName.SCRIPT, "src"),
        LINK(HTMLElementName.LINK, "href");

        final String tag;
        final String attribute;

        SupportedElements(String tag, String attribute) {
            this.tag = tag;
            this.attribute = attribute;
        }

        public static boolean contains(String tag) {
            return Stream.of(values()).anyMatch(e -> tag.equals(e.tag));
        }

        public static Optional<String> getHost(Element element, String origin) {
            String url =
                    element.getAttributeValue(
                            SupportedElements.valueOf(element.getName().toUpperCase(Locale.ROOT))
                                    .attribute);
            if (url == null || url.startsWith("data:")) {
                return Optional.of(origin);
            }
            URI uri = null;

            try {
                uri = new URI(url);
            } catch (URISyntaxException e) {
                return Optional.empty();
            }
            if (!uri.isAbsolute()) {
                return Optional.of(origin);
            }
            return Optional.ofNullable(uri.getHost());
        }
    }

    /** Prefix for internationalized messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanalpha.sri-integrity.";

    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
                    CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG);

    private final TrustedDomains trustedDomains = new TrustedDomains();

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        trustedDomains.update(getConfig().getString(RuleConfigParam.RULE_DOMAINS_TRUSTED, ""));
        trustedDomains.add(new RegexTrust(msg.getRequestHeader().getHostName()));

        SiteMap tree = Model.getSingleton().getSession().getSiteTree();
        List<Element> sourceElements = source.getAllElements();
        List<Element> impactedElements =
                sourceElements.stream()
                        .filter(element -> SupportedElements.contains(element.getName()))
                        .filter(isNotTrusted(trustedDomains, msg.getRequestHeader().getHostName()))
                        .collect(Collectors.toList());
        if (!impactedElements.isEmpty()) {
            impactedElements.forEach(
                    element ->
                            newAlert()
                                    .setRisk(Alert.RISK_MEDIUM)
                                    .setConfidence(Alert.CONFIDENCE_HIGH)
                                    .setDescription(getString("desc"))
                                    .setSolution(getString("soln"))
                                    .setReference(getString("refs"))
                                    .setEvidence(element.toString())
                                    .setCweId(345) // CWE-345: Insufficient Verification of Data
                                    // Authenticity
                                    .setWascId(15) // Application Misconfiguration
                                    .setOtherInfo(getOtherInfo(msg, element, tree))
                                    .raise());
        }
    }

    private String calculateIntegrityHash(HttpMessage msg, Element element, SiteMap tree) {
        String src = element.getAttributeValue("src");
        if (src == null) {
            return "";
        }
        String integrityHash = "";
        try {
            URI newUri = new URI(msg.getRequestHeader().getURI().toString()).resolve(src);
            SiteNode node =
                    tree.findNode(new org.apache.commons.httpclient.URI(newUri.toString(), true));
            HttpMessage scriptNodeMessage = node.getHistoryReference().getHttpMessage();
            if (scriptNodeMessage.isResponseFromTargetHost()) {
                integrityHash =
                        "sha384-"
                                + Base64.getEncoder()
                                        .encodeToString(
                                                DigestUtils.sha384(
                                                        scriptNodeMessage
                                                                .getResponseBody()
                                                                .toString()));
            }
        } catch (Exception e) {
            logger.debug("Error occured while calculating the hash. Error: {}", e.getMessage(), e);
        }
        return integrityHash;
    }

    private String getOtherInfo(HttpMessage msg, Element element, SiteMap tree) {
        String integrityHash = calculateIntegrityHash(msg, element, tree);
        if (integrityHash.isEmpty()) {
            return "";
        }
        return Constant.messages.getString(MESSAGE_PREFIX + "otherinfo", integrityHash);
    }

    private static Predicate<Element> isNotTrusted(TrustedDomains trustedDomains, String origin) {
        return element -> {
            Optional<String> maybeResourceUri = SupportedElements.getHost(element, origin);
            return element.getAttributeValue("integrity") == null
                    && !"canonical".equalsIgnoreCase(element.getAttributeValue("rel"))
                    && !maybeResourceUri.map(trustedDomains::isIncluded).orElse(false);
        };
    }

    @Override
    public String getName() {
        return getString("name");
    }

    private static String getString(String param) {
        return Constant.messages.getString(MESSAGE_PREFIX + param);
    }

    @Override
    public int getPluginId() {
        return 90003;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }
}
