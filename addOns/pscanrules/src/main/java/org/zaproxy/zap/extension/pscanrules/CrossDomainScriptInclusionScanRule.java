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
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.model.Context;

public class CrossDomainScriptInclusionScanRule extends PluginPassiveScanner {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanrules.crossdomainscriptinclusion.";

    private static final int PLUGIN_ID = 10017;

    private static final Logger logger = Logger.getLogger(CrossDomainScriptInclusionScanRule.class);
    private Model model = null;

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {}

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        if (msg.getResponseBody().length() > 0 && msg.getResponseHeader().isHtml()) {
            List<Element> sourceElements = source.getAllElements(HTMLElementName.SCRIPT);
            if (sourceElements != null) {
                for (Element sourceElement : sourceElements) {
                    String src = sourceElement.getAttributeValue("src");
                    if (src != null
                            && isScriptFromOtherDomain(
                                    msg.getRequestHeader().getHostName(), src, msg)) {
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

    private void raiseAlert(HttpMessage msg, int id, String crossDomainScript, String evidence) {
        newAlert()
                .setRisk(Alert.RISK_LOW)
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setDescription(getDescription())
                .setParam(crossDomainScript)
                .setSolution(getSolution())
                .setEvidence(evidence)
                .setCweId(829) // CWE Id 829 - Inclusion of Functionality from Untrusted Control
                // Sphere
                .setWascId(15) // WASC Id 15 - Application Misconfiguration
                .raise();
    }

    @Override
    public void setParent(PassiveScanThread parent) {
        // Nothing to do.
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
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
            logger.debug("Error: " + e.getMessage());
        }
        return otherDomain;
    }
}
