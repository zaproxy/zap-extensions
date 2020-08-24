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

import java.util.ArrayList;
import java.util.List;
import net.htmlparser.jericho.Attribute;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.anticsrf.ExtensionAntiCSRF;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.extension.ruleconfig.RuleConfigParam;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

/**
 * The CsrfCountermeasuresScanRule identifies *potential* vulnerabilities with the lack of known
 * CSRF countermeasures in pages with forms.
 *
 * @author 70pointer
 */
public class CsrfCountermeasuresScanRule extends PluginPassiveScanner {

    /** contains the base vulnerability that this plugin refers to */
    private static Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_9");

    private ExtensionAntiCSRF extensionAntiCSRF;
    private String csrfIgnoreList;
    private String csrfAttIgnoreList;
    private String csrfValIgnoreList;

    /** the logger */
    private static Logger logger = Logger.getLogger(CsrfCountermeasuresScanRule.class);

    @Override
    public void setParent(PassiveScanThread parent) {
        // Nothing to do.
    }

    /** does nothing. The request itself is not scanned. Only the response is scanned. */
    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        // Ignore
    }

    /**
     * gets the plugin id for this extension
     *
     * @return the plugin id for this extension
     */
    @Override
    public int getPluginId() {
        return 10202;
    }

    /**
     * scans each form in the HTTP response for known anti-CSRF tokens. If any form exists that does
     * not contain a known anti-CSRF token, raise an alert.
     */
    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        if (AlertThreshold.HIGH.equals(getAlertThreshold()) && !msg.isInScope()) {
            return; // At HIGH threshold return if the msg isn't in scope
        }

        // need to do this if we are to be able to get an element's parent. Do it as early as
        // possible in the logic
        source.fullSequentialParse();

        long start = System.currentTimeMillis();

        ExtensionAntiCSRF extAntiCSRF = getExtensionAntiCSRF();

        if (extAntiCSRF == null) {
            return;
        }

        List<Element> formElements = source.getAllElements(HTMLElementName.FORM);
        List<String> tokenNames = extAntiCSRF.getAntiCsrfTokenNames();

        if (formElements != null && formElements.size() > 0) {
            boolean hasSecurityAnnotation = false;

            // Loop through all of the FORM tags
            logger.debug("Found " + formElements.size() + " forms");

            int numberOfFormsPassed = 0;

            List<String> ignoreList = new ArrayList<String>();
            String ignoreConf = getCSRFIgnoreList();
            if (ignoreConf != null && ignoreConf.length() > 0) {
                logger.debug("Using ignore list: " + ignoreConf);
                for (String str : ignoreConf.split(",")) {
                    String strTrim = str.trim();
                    if (strTrim.length() > 0) {
                        ignoreList.add(strTrim);
                    }
                }
            }
            String ignoreAttName = getCSRFIgnoreAttName();
            String ignoreAttValue = getCSRFIgnoreAttValue();

            for (Element formElement : formElements) {
                logger.debug(
                        "FORM ["
                                + formElement
                                + "] has parent ["
                                + formElement.getParentElement()
                                + "]");
                StringBuilder sbForm = new StringBuilder();
                ++numberOfFormsPassed;
                // if the form has no parent, it is pretty likely invalid HTML (or Javascript!!!),
                // so we will not report
                // any alerts on it.
                // ie. This logic is necessary to eliminate false positives on non-HTML files.
                if (formElement.getParentElement() == null) {
                    logger.debug(
                            "Skipping HTML form because it has no parent. Likely not actually HTML.");
                    continue; // do not report a missing anti-CSRF field on this form
                }
                if (formOnIgnoreList(formElement, ignoreList)) {
                    continue;
                }
                if (!StringUtils.isEmpty(ignoreAttName)) {
                    // Check to see if the specific security annotation is present
                    Attribute att = formElement.getAttributes().get(ignoreAttName);
                    if (att != null) {
                        if (StringUtils.isEmpty(ignoreAttValue)
                                || ignoreAttValue.equals(att.getValue())) {
                            hasSecurityAnnotation = true;
                        }
                    }
                }

                List<Element> inputElements = formElement.getAllElements(HTMLElementName.INPUT);
                sbForm.append("[Form " + numberOfFormsPassed + ": ");
                boolean foundCsrfToken = false;

                if (inputElements != null && inputElements.size() > 0) {
                    // Loop through all of the INPUT elements
                    logger.debug("Found " + inputElements.size() + " inputs");
                    for (Element inputElement : inputElements) {
                        String attId = inputElement.getAttributeValue("ID");
                        if (attId != null) {
                            sbForm.append("\"" + attId + "\" ");
                            for (String tokenName : tokenNames) {
                                if (tokenName.equalsIgnoreCase(attId)) {
                                    foundCsrfToken = true;
                                    break;
                                }
                            }
                        }
                        String name = inputElement.getAttributeValue("NAME");
                        if (name != null) {
                            if (attId == null) {
                                // Dont bother recording both
                                sbForm.append("\"" + name + "\" ");
                            }
                            for (String tokenName : tokenNames) {
                                if (tokenName.equalsIgnoreCase(name)) {
                                    foundCsrfToken = true;
                                    break;
                                }
                            }
                        }
                    }
                }
                if (foundCsrfToken) {
                    continue;
                }

                String evidence = "";
                evidence = formElement.getFirstElement().getStartTag().toString();

                sbForm.append(']');

                String formDetails = sbForm.toString();
                String tokenNamesFlattened = tokenNames.toString();

                int risk = Alert.RISK_LOW;
                String desc = Constant.messages.getString("pscanrules.noanticsrftokens.desc");
                String extraInfo =
                        Constant.messages.getString(
                                "pscanrules.noanticsrftokens.alert.extrainfo",
                                tokenNamesFlattened,
                                formDetails);
                if (hasSecurityAnnotation) {
                    risk = Alert.RISK_INFO;
                    extraInfo =
                            Constant.messages.getString(
                                    "pscanrules.noanticsrftokens.extrainfo.annotation");
                }

                newAlert()
                        .setRisk(risk)
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setDescription(desc + "\n" + getDescription())
                        .setOtherInfo(extraInfo)
                        .setSolution(getSolution())
                        .setReference(getReference())
                        .setEvidence(evidence)
                        .setCweId(352) // CWE-352: Cross-Site Request Forgery (CSRF)
                        .setWascId(9)
                        .raise();
            }
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

    private boolean formOnIgnoreList(Element formElement, List<String> ignoreList) {
        String id = formElement.getAttributeValue("id");
        String name = formElement.getAttributeValue("name");
        for (String ignore : ignoreList) {
            if (ignore.equals(id)) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Ignoring form with id = " + id);
                }
                return true;
            } else if (ignore.equals(name)) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Ignoring form with name = " + name);
                }
                return true;
            }
        }
        return false;
    }

    @Override
    public String getName() {
        // do not use the name of the related vulnerability
        // (because we have not actually discovered an instance of this vulnerability class!)
        return Constant.messages.getString("pscanrules.noanticsrftokens.name");
    }

    public String getDescription() {
        if (vuln != null) {
            return vuln.getDescription();
        }
        return "Failed to load vulnerability description from file";
    }

    public String getSolution() {
        if (vuln != null) {
            return vuln.getSolution();
        }
        return "Failed to load vulnerability solution from file";
    }

    public String getReference() {
        if (vuln != null) {
            StringBuilder sb = new StringBuilder();
            for (String ref : vuln.getReferences()) {
                if (sb.length() > 0) {
                    sb.append('\n');
                }
                sb.append(ref);
            }
            return sb.toString();
        }
        return "Failed to load vulnerability reference from file";
    }

    protected ExtensionAntiCSRF getExtensionAntiCSRF() {
        if (extensionAntiCSRF == null) {
            return Control.getSingleton()
                    .getExtensionLoader()
                    .getExtension(ExtensionAntiCSRF.class);
        }
        return extensionAntiCSRF;
    }

    protected void setExtensionAntiCSRF(ExtensionAntiCSRF extensionAntiCSRF) {
        this.extensionAntiCSRF = extensionAntiCSRF;
    }

    protected String getCSRFIgnoreList() {
        if (csrfIgnoreList == null) {
            return Model.getSingleton()
                    .getOptionsParam()
                    .getConfig()
                    .getString(RuleConfigParam.RULE_CSRF_IGNORE_LIST);
        }
        return csrfIgnoreList;
    }

    protected void setCsrfIgnoreList(String csrfIgnoreList) {
        this.csrfIgnoreList = csrfIgnoreList;
    }

    protected String getCSRFIgnoreAttName() {
        if (csrfAttIgnoreList == null) {
            return Model.getSingleton()
                    .getOptionsParam()
                    .getConfig()
                    .getString(RuleConfigParam.RULE_CSRF_IGNORE_ATT_NAME, null);
        }
        return csrfAttIgnoreList;
    }

    protected void setCSRFIgnoreAttName(String csrfAttIgnoreList) {
        this.csrfAttIgnoreList = csrfAttIgnoreList;
    }

    protected String getCSRFIgnoreAttValue() {
        if (csrfValIgnoreList == null) {
            return Model.getSingleton()
                    .getOptionsParam()
                    .getConfig()
                    .getString(RuleConfigParam.RULE_CSRF_IGNORE_ATT_VALUE, null);
        }
        return csrfValIgnoreList;
    }

    protected void setCSRFIgnoreAttValue(String csrfValIgnoreList) {
        this.csrfValIgnoreList = csrfValIgnoreList;
    }
}
