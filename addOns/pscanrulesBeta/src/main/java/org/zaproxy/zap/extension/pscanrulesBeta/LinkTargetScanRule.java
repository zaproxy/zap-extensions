/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.http.domains.TrustedDomains;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.extension.ruleconfig.RuleConfigParam;
import org.zaproxy.zap.model.Context;

public class LinkTargetScanRule extends PluginPassiveScanner {

    public static final String TRUSTED_DOMAINS_PROPERTY = RuleConfigParam.RULE_DOMAINS_TRUSTED;
    private static final String MESSAGE_PREFIX = "pscanbeta.linktarget.";

    private static final String REL_ATTRIBUTE = "rel";
    private static final String TARGET_ATTRIBUTE = "target";
    private static final String BLANK = "_blank";
    private static final String OPENER = "opener";
    private static final String NOOPENER = "noopener";
    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN,
                    CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG);

    private final TrustedDomains trustedDomains = new TrustedDomains();

    private Model model = null;

    private static final Logger LOG = LogManager.getLogger(LinkTargetScanRule.class);

    @Override
    public int getPluginId() {
        return 10108;
    }

    private Model getModel() {
        if (this.model == null) {
            this.model = Model.getSingleton();
        }
        return this.model;
    }

    /*
     * Just for use in the unit tests
     */
    protected void setModel(Model model) {
        this.model = model;
    }

    private boolean isLinkFromOtherDomain(String host, String link, List<Context> contextList) {
        if (link == null
                || !link.startsWith("//")
                        && (link.startsWith("/")
                                || link.startsWith("./")
                                || link.startsWith("../"))) {
            return false;
        }
        boolean otherDomain = false;
        try {
            URI linkURI = new URI(link, true);
            String linkURIStr = linkURI.toString();
            String linkHost = linkURI.getHost();
            if (linkHost != null && !linkHost.equalsIgnoreCase(host)) {
                otherDomain = true;
            }
            if (otherDomain && !Plugin.AlertThreshold.LOW.equals(this.getAlertThreshold())) {
                // Get a list of contexts that contain the original URL
                for (Context context : contextList) {
                    if (context.isInContext(linkURIStr)) {
                        // The linkURI is in a context that the original URI is in
                        return false; // No need to loop further
                    }
                }
            }
        } catch (URIException e) {
            // Ignore
        }
        return otherDomain && !trustedDomains.isIncluded(link);
    }

    private boolean checkElement(Element link) {
        // get target, check if its _blank
        String target = link.getAttributeValue(TARGET_ATTRIBUTE);

        if (target == null) {
            return false;
        }

        if (AlertThreshold.HIGH.equals(this.getAlertThreshold())
                && !BLANK.equalsIgnoreCase(target)) {
            // Only report _blank link targets at a high threshold
            return false;
        }
        // Not looking good,
        String relAtt = link.getAttributeValue(REL_ATTRIBUTE);
        if (relAtt != null) {
            relAtt = relAtt.toLowerCase();
            if (relAtt.contains(OPENER) && !relAtt.contains(NOOPENER)) {
                newAlert()
                        .setRisk(Alert.RISK_MEDIUM)
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setDescription(getDescription())
                        .setSolution(getSolution())
                        .setReference(getReference())
                        .setEvidence(link.toString())
                        .raise();
                return true;
            }
        }
        return false;
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        if (msg.getResponseBody().length() == 0 || !msg.getResponseHeader().isHtml()) {
            // No point attempting to parse non-HTML content, it will not be correctly interpreted.
            return;
        }
        // Check to see if the configs have changed
        trustedDomains.update(getConfig().getString(RuleConfigParam.RULE_DOMAINS_TRUSTED, ""));

        String host = msg.getRequestHeader().getHostName();
        List<Context> contextList =
                getModel()
                        .getSession()
                        .getContextsForUrl(msg.getRequestHeader().getURI().toString());

        List<Element> elements = new ArrayList<>(source.getAllElements(HTMLElementName.A));
        elements.addAll(source.getAllElements(HTMLElementName.AREA));
        for (Element link : elements) {
            if (isLinkFromOtherDomain(host, link.getAttributeValue("href"), contextList)
                    && checkElement(link)) {
                return;
            }
        }
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    private String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    private String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    private String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }
}
