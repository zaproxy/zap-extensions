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
package org.zaproxy.zap.extension.pscanrulesBeta;

import java.util.List;
import java.util.Map;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.model.Tech;

/**
 * Servlet Parameter Pollution rule. Suggested by Jeff Williams on the OWASP Leaders List:
 * http://lists.owasp.org/pipermail/owasp-leaders/2012-July/007521.html
 *
 * @author psiinon
 */
public class ServletParameterPollutionScanRule extends PluginPassiveScanner
        implements CommonPassiveScanRuleInfo {

    private static final String MESSAGE_PREFIX = "pscanbeta.servletparameterpollution.";
    private static final int PLUGIN_ID = 10026;
    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN,
                    CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG);
    private static final Logger LOGGER =
            LogManager.getLogger(ServletParameterPollutionScanRule.class);

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        if (!AlertThreshold.LOW.equals(this.getAlertThreshold())
                || !getHelper().getTechSet().includes(Tech.JSP_SERVLET)) {
            return;
        }

        List<Element> formElements = source.getAllElements(HTMLElementName.FORM);

        if (formElements != null && !formElements.isEmpty()) {
            // Loop through all of the FORM tags
            LOGGER.debug("Found {} forms", formElements.size());

            // check for 'target' param

            for (Element formElement : formElements) {
                boolean actionMissingOrEmpty =
                        StringUtils.isEmpty(formElement.getAttributeValue("action"));

                if (actionMissingOrEmpty) {
                    // evidence - just include the first <form ..> element
                    createAlert(formElement.getFirstStartTag().toString()).raise();
                    // Only raise one alert per page
                    return;
                }
            }
        }
    }

    private AlertBuilder createAlert(String evidence) {
        return newAlert()
                .setRisk(Alert.RISK_MEDIUM)
                .setConfidence(Alert.CONFIDENCE_LOW)
                .setDescription(getDescription())
                .setSolution(getSolution())
                .setReference(getReference())
                .setEvidence(evidence)
                .setCweId(20) // CWE Id 20 - Improper Input Validation
                .setWascId(20); // WASC Id 20 - Improper Input Handling
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

    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(createAlert("<form />").build());
    }
}
