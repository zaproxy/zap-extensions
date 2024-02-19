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
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.http.domains.TrustedDomains;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.extension.ruleconfig.RuleConfigParam;
import org.zaproxy.zap.model.Context;

public class CrossDomainScriptInclusionScanRule extends PluginPassiveScanner
        implements CommonPassiveScanRuleInfo {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanrules.crossdomainscriptinclusion.";

    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(CommonAlertTag.OWASP_2021_A08_INTEGRITY_FAIL);

    private static final int PLUGIN_ID = 10017;

    private static final Logger LOGGER =
            LogManager.getLogger(CrossDomainScriptInclusionScanRule.class);
    private Model model = null;

    private final TrustedDomains trustedDomains = new TrustedDomains();

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        trustedDomains.update(getConfig().getString(RuleConfigParam.RULE_DOMAINS_TRUSTED, ""));

        if (msg.getResponseBody().length() > 0 && msg.getResponseHeader().isHtml()) {
            List<Element> sourceElements = source.getAllElements(HTMLElementName.SCRIPT);
            if (sourceElements != null) {
                for (Element sourceElement : sourceElements) {
                    String src = sourceElement.getAttributeValue("src");
                    if (src != null
                            && isScriptFromOtherDomain(
                                    msg.getRequestHeader().getHostName(), src, msg)
                            && !trustedDomains.isIncluded(src)) {
                        String integrity = sourceElement.getAttributeValue("integrity");
                        if (integrity == null || integrity.trim().length() == 0) {
                            /*
                             * If it has an integrity value assume its fine
                             * We dont check the integrity value is valid because
                             * 1. pscan rules cant make new requests and
                             * 2. the browser will check it anyway
                             */
                            this.raiseAlert(msg, id, src, sourceElement.toString());
                        }
                    }
                }
            }
        }
    }

    private AlertBuilder createAlert(String crossDomainScript, String evidence) {
        return newAlert()
                .setRisk(getRisk())
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setDescription(getDescription())
                .setParam(crossDomainScript)
                .setSolution(getSolution())
                .setEvidence(evidence)
                .setCweId(getCweId())
                .setWascId(getWascId());
    }

    private void raiseAlert(HttpMessage msg, int id, String crossDomainScript, String evidence) {
        createAlert(crossDomainScript, evidence).raise();
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(
                createAlert(
                                "http://externalDomain.example.com/weatherwidget.js",
                                "<script type=\"text/javascript\" src=\"http://externalDomain.example.com/weatherwidget.js\"></script>")
                        .build());
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    public int getRisk() {
        return Alert.RISK_LOW;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    public int getCweId() {
        return 829; // CWE Id 829 - Inclusion of Functionality from Untrusted Control Sphere
    }

    public int getWascId() {
        return 15; // WASC-15: Application Misconfiguration)
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

    private boolean isScriptFromOtherDomain(String host, String scriptURL, HttpMessage msg) {
        if (!scriptURL.startsWith("//")
                && (scriptURL.startsWith("/")
                        || scriptURL.startsWith("./")
                        || scriptURL.startsWith("../"))) {
            return false;
        }
        boolean otherDomain = false;
        try {
            URI scriptURI = new URI(scriptURL, true);
            String scriptURIStr = scriptURI.toString();
            String scriptHost = scriptURI.getHost();
            if (scriptHost != null && !scriptHost.toLowerCase().equals(host.toLowerCase())) {
                otherDomain = true;
            }
            if (otherDomain && !Plugin.AlertThreshold.LOW.equals(this.getAlertThreshold())) {
                // Get a list of contexts that contain the original URL
                List<Context> contextList =
                        getModel()
                                .getSession()
                                .getContextsForUrl(msg.getRequestHeader().getURI().toString());
                for (Context context : contextList) {
                    if (context.isInContext(scriptURIStr)) {
                        // The scriptURI is in a context that the original URI is in
                        // At MEDIUM and HIGH Threshold consider this an OK cross domain inclusion
                        return false; // No need to loop further
                    }
                }
            }
        } catch (URIException e) {
            LOGGER.debug("Error: {}", e.getMessage());
        }
        return otherDomain;
    }
}
