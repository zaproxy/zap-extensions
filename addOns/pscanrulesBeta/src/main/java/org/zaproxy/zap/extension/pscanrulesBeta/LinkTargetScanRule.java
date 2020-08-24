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
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.extension.ruleconfig.RuleConfigParam;
import org.zaproxy.zap.model.Context;

public class LinkTargetScanRule extends PluginPassiveScanner {

    public static final String TRUSTED_DOMAINS_PROPERTY = RuleConfigParam.RULE_DOMAINS_TRUSTED;
    private static final String MESSAGE_PREFIX = "pscanbeta.linktarget.";

    private static final String REL_ATTRIBUTE = "rel";
    private static final String TARGET_ATTRIBUTE = "target";
    private static final String _BLANK = "_blank";
    private static final String NOOPENER = "noopener";
    private static final String NOREFERRER = "noreferrer";

    private String trustedConfig = "";
    private List<String> trustedDomainRegexes = new ArrayList<String>();

    private Model model = null;

    private static final Logger LOG = Logger.getLogger(PluginPassiveScanner.class);

    @Override
    public void setParent(PassiveScanThread parent) {
        // Nothing to do.
    }

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {}

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
            if (linkHost != null && !linkHost.toLowerCase().equals(host.toLowerCase())) {
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
        if (otherDomain) {
            // check the trusted domains
            for (String regex : this.trustedDomainRegexes) {
                try {
                    if (link.matches(regex)) {
                        return false;
                    }
                } catch (Exception e) {
                    LOG.warn("Invalid regex in rule " + TRUSTED_DOMAINS_PROPERTY + ": " + regex, e);
                }
            }
        }
        return otherDomain;
    }

    private void checkIgnoreList() {
        String trustedConf = getConfig().getString(TRUSTED_DOMAINS_PROPERTY, "");
        if (!trustedConf.equals(this.trustedConfig)) {
            // Its changed
            trustedDomainRegexes.clear();
            this.trustedConfig = trustedConf;
            for (String regex : trustedConf.split(",")) {
                String regexTrim = regex.trim();
                if (regexTrim.length() > 0) {
                    trustedDomainRegexes.add(regexTrim);
                }
            }
        }
    }

    private boolean checkElement(Element link, HttpMessage msg, int id) {
        // get target, check if its _blank
        String target = link.getAttributeValue(TARGET_ATTRIBUTE);
        if (target != null) {
            if (AlertThreshold.HIGH.equals(this.getAlertThreshold())
                    && !_BLANK.equalsIgnoreCase(target)) {
                // Only report _blank link targets at a high threshold
                return false;
            }
            // Not looking good,
            String relAtt = link.getAttributeValue(REL_ATTRIBUTE);
            if (relAtt != null) {
                relAtt = relAtt.toLowerCase();
                if (relAtt.contains(NOOPENER) && relAtt.contains(NOREFERRER)) {
                    // Its ok
                    return false;
                }
            }
            // Its bad
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
        return false;
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        if (msg.getResponseBody().length() == 0 || !msg.getResponseHeader().isHtml()) {
            // No point attempting to parse non-HTML content, it will not be correctly interpreted.
            return;
        }
        // Check to see if the configs have changed
        checkIgnoreList();

        String host = msg.getRequestHeader().getHostName();
        List<Context> contextList =
                getModel()
                        .getSession()
                        .getContextsForUrl(msg.getRequestHeader().getURI().toString());

        for (Element link : source.getAllElements(HTMLElementName.A)) {
            if (this.isLinkFromOtherDomain(host, link.getAttributeValue("href"), contextList)) {
                if (this.checkElement(link, msg, id)) {
                    return;
                }
            }
        }
        for (Element link : source.getAllElements(HTMLElementName.AREA)) {
            if (this.isLinkFromOtherDomain(host, link.getAttributeValue("href"), contextList)) {
                if (this.checkElement(link, msg, id)) {
                    return;
                }
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
}
