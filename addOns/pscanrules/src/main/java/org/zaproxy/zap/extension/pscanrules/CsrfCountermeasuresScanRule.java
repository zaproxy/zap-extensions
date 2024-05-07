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
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;
import net.htmlparser.jericho.Attribute;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerabilities;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerability;
import org.zaproxy.zap.extension.anticsrf.ExtensionAntiCSRF;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.extension.ruleconfig.RuleConfigParam;

/**
 * The CsrfCountermeasuresScanRule identifies *potential* vulnerabilities with the lack of known
 * CSRF countermeasures in pages with forms.
 *
 * @author 70pointer
 */
public class CsrfCountermeasuresScanRule extends PluginPassiveScanner
        implements CommonPassiveScanRuleInfo {

    /** contains the base vulnerability that this plugin refers to */
    private static final Vulnerability VULN = Vulnerabilities.getDefault().get("wasc_9");

    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A01_BROKEN_AC,
                    CommonAlertTag.OWASP_2017_A05_BROKEN_AC,
                    CommonAlertTag.WSTG_V42_SESS_05_CSRF);

    private ExtensionAntiCSRF extensionAntiCSRF;
    private String csrfIgnoreList;
    private String csrfAttIgnoreList;
    private String csrfValIgnoreList;

    /** the logger */
    private static final Logger LOGGER = LogManager.getLogger(CsrfCountermeasuresScanRule.class);

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
        if (AlertThreshold.HIGH.equals(getAlertThreshold()) && !msg.isInScope()
                || !msg.getResponseHeader().isHtml()) {
            return;
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

        if (formElements != null && !formElements.isEmpty()) {
            boolean hasSecurityAnnotation = false;

            // Loop through all of the FORM tags
            LOGGER.debug("Found {} forms", formElements.size());

            int numberOfFormsPassed = 0;

            List<String> ignoreList = new ArrayList<>();
            String ignoreConf = getCSRFIgnoreList();
            if (ignoreConf != null && !ignoreConf.isEmpty()) {
                LOGGER.debug("Using ignore list: {}", ignoreConf);
                for (String str : ignoreConf.split(",")) {
                    String strTrim = str.trim();
                    if (!strTrim.isEmpty()) {
                        ignoreList.add(strTrim);
                    }
                }
            }
            String ignoreAttName = getCSRFIgnoreAttName();
            String ignoreAttValue = getCSRFIgnoreAttValue();

            for (Element formElement : formElements) {
                LOGGER.debug(
                        "FORM [{}] has parent [{}]", formElement, formElement.getParentElement());
                StringBuilder sbForm = new StringBuilder();
                SortedSet<String> elementNames = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
                ++numberOfFormsPassed;
                // if the form has no parent, it is pretty likely invalid HTML,
                // so we will not report
                // any alerts on it.
                if (formElement.getParentElement() == null) {
                    LOGGER.debug(
                            "Skipping HTML form because it has no parent. Likely not actually valid HTML.");
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
                sbForm.append("[Form " + numberOfFormsPassed + ": \"");
                boolean foundCsrfToken = false;

                if (inputElements != null && !inputElements.isEmpty()) {
                    // Loop through all of the INPUT elements
                    LOGGER.debug("Found {} inputs", inputElements.size());
                    for (Element inputElement : inputElements) {
                        String attId = inputElement.getAttributeValue("ID");
                        if (attId != null) {
                            elementNames.add(attId);
                            foundCsrfToken |= extAntiCSRF.isAntiCsrfToken(attId);
                        }
                        String name = inputElement.getAttributeValue("NAME");
                        if (name != null) {
                            if (attId == null) {
                                // Dont bother recording both
                                elementNames.add(name);
                            }
                            foundCsrfToken |= extAntiCSRF.isAntiCsrfToken(name);
                        }
                    }
                }
                if (foundCsrfToken) {
                    continue;
                }

                String evidence = "";
                evidence = formElement.getFirstElement().getStartTag().toString();

                // Append the form names with double quotes
                sbForm.append(String.join("\" \"", elementNames));
                sbForm.append("\" ]");

                String formDetails = sbForm.toString();
                String tokenNamesFlattened = extAntiCSRF.getAntiCsrfTokenNames().toString();

                int risk = Alert.RISK_MEDIUM;
                String desc = Constant.messages.getString("pscanrules.noanticsrftokens.desc");
                String extraInfo = getExtraInfo(tokenNamesFlattened, formDetails);
                if (hasSecurityAnnotation) {
                    risk = Alert.RISK_INFO;
                    extraInfo =
                            Constant.messages.getString(
                                    "pscanrules.noanticsrftokens.extrainfo.annotation");
                }

                buildAlert(risk, desc, extraInfo, evidence).raise();
            }
        }
        LOGGER.debug("\tScan of record {} took {} ms", id, System.currentTimeMillis() - start);
    }

    private String getExtraInfo(String tokenNamesFlattened, String formDetails) {
        return Constant.messages.getString(
                "pscanrules.noanticsrftokens.alert.extrainfo", tokenNamesFlattened, formDetails);
    }

    private boolean formOnIgnoreList(Element formElement, List<String> ignoreList) {
        String id = formElement.getAttributeValue("id");
        String name = formElement.getAttributeValue("name");
        for (String ignore : ignoreList) {
            if (ignore.equals(id)) {
                LOGGER.debug("Ignoring form with id = {}", id);
                return true;
            } else if (ignore.equals(name)) {
                LOGGER.debug("Ignoring form with name = {}", name);
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
        return VULN.getDescription();
    }

    public String getSolution() {
        return VULN.getSolution();
    }

    public String getReference() {
        return VULN.getReferencesAsString();
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    public int getCweId() {
        return 352; // CWE-352: Cross-Site Request Forgery (CSRF)
    }

    public int getWascId() {
        return 9;
    }

    private AlertBuilder buildAlert(int risk, String desc, String extraInfo, String evidence) {
        return newAlert()
                .setRisk(risk)
                .setConfidence(Alert.CONFIDENCE_LOW)
                .setDescription(desc + "\n" + getDescription())
                .setOtherInfo(extraInfo)
                .setSolution(getSolution())
                .setReference(getReference())
                .setEvidence(evidence)
                .setCweId(getCweId())
                .setWascId(getWascId());
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(
                buildAlert(
                                Alert.RISK_MEDIUM,
                                Constant.messages.getString("pscanrules.noanticsrftokens.desc"),
                                getExtraInfo(
                                        "[token, csrfToken, csrf-token]", "[Form 1: \"name\" ]"),
                                "<form name=\"someName\" data-no-csrf>")
                        .build());
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
