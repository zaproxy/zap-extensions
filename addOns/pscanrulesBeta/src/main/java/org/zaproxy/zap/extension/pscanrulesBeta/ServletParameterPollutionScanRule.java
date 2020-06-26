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
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.model.Tech;

/**
 * Servlet Parameter Pollution rule. Suggested by Jeff Williams on the OWASP Leaders List:
 * http://lists.owasp.org/pipermail/owasp-leaders/2012-July/007521.html
 *
 * @author psiinon
 */
public class ServletParameterPollutionScanRule extends PluginPassiveScanner {

    private static final String MESSAGE_PREFIX = "pscanbeta.servletparameterpollution.";
    private static final int PLUGIN_ID = 10026;

    private static final Logger logger = Logger.getLogger(ServletParameterPollutionScanRule.class);

    @Override
    public void setParent(PassiveScanThread parent) {
        // Nothing to do.
    }

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        // Ignore
    }

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

        if (formElements != null && formElements.size() > 0) {
            // Loop through all of the FORM tags
            logger.debug("Found " + formElements.size() + " forms");

            // check for 'target' param

            for (Element formElement : formElements) {
                boolean actionMissingOrEmpty =
                        StringUtils.isEmpty(formElement.getAttributeValue("action"));

                if (actionMissingOrEmpty) {
                    newAlert()
                            .setRisk(Alert.RISK_MEDIUM)
                            .setConfidence(Alert.CONFIDENCE_LOW)
                            .setDescription(getDescription())
                            .setSolution(getSolution())
                            .setReference(getReference())
                            .setEvidence(
                                    formElement
                                            .getFirstStartTag()
                                            .toString()) // evidence - just include the first <form
                            // ..>
                            // element
                            .setCweId(20) // CWE Id 20 - Improper Input Validation
                            .setWascId(20) // WASC Id 20 - Improper Input Handling
                            .raise();
                    // Only raise one alert per page
                    return;
                }
            }
        }
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
}
