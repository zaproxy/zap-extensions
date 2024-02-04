/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.oast.ExtensionOast;
import org.zaproxy.addon.oast.OastPayload;

public class SsrfScanRule extends AbstractAppParamPlugin implements CommonActiveScanRuleInfo {

    private static final int PLUGIN_ID = 40046;
    private static final Logger LOGGER = LogManager.getLogger(SsrfScanRule.class);

    @Override
    public int getId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("ascanbeta.ssrf.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("ascanbeta.ssrf.desc");
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString("ascanbeta.ssrf.soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString("ascanbeta.ssrf.refs");
    }

    @Override
    public int getCweId() {
        return 918;
    }

    @Override
    public int getWascId() {
        return 20;
    }

    @Override
    public Map<String, String> getAlertTags() {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2021_A10_SSRF,
                                CommonAlertTag.WSTG_V42_INPV_19_SSRF));
        alertTags.put(ExtensionOast.OAST_ALERT_TAG_KEY, ExtensionOast.OAST_ALERT_TAG_VALUE);
        return alertTags;
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(
                newAlert()
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setAttack("https://12345.oast.example.com")
                        .setOtherInfo(
                                Constant.messages.getString(
                                        "ascanbeta.ssrf.otherinfo.canaryinbody"))
                        .setEvidence("54321")
                        .build());
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
            getParent().pluginSkipped(this, Constant.messages.getString("ascanbeta.ssrf.skipped"));
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
            LOGGER.warn("Could not perform SSRF Attack.");
        }
    }

    private void scanWithCallbackService(String param) {
        ExtensionOast extOast =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionOast.class);
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
                            alert, SsrfScanRule.class.getSimpleName());
            alert.setAttack(payload);
            setParameter(msg, param, payload);
            sendAndReceive(msg);
        } catch (IOException e) {
            LOGGER.warn(e.getMessage(), e);
        }
    }

    private void scanWithExternalOastService(String param) throws Exception {
        ExtensionOast extOast =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionOast.class);
        try {
            HttpMessage msg = getNewMsg();
            Alert alert =
                    newAlert()
                            .setConfidence(Alert.CONFIDENCE_MEDIUM)
                            .setMessage(msg)
                            .setSource(Alert.Source.ACTIVE)
                            .build();
            String[] schemes = {HttpHeader.SCHEME_HTTP, HttpHeader.SCHEME_HTTPS};
            for (String scheme : schemes) {
                OastPayload oastPayload = extOast.registerAlertAndGetOastPayload(alert);
                String payload = scheme + oastPayload.getPayload();
                alert.setParam(param);
                alert.setAttack(payload);
                setParameter(msg, param, payload);
                sendAndReceive(msg);
                if (msg.getResponseBody().toString().contains(oastPayload.getCanary())) {
                    alert.setOtherInfo(
                            Constant.messages.getString("ascanbeta.ssrf.otherinfo.canaryinbody"));
                    alert.setEvidence(oastPayload.getCanary());
                    getParent().alertFound(alert);
                    break;
                }
            }
        } catch (IOException e) {
            LOGGER.warn(e.getMessage(), e);
        }
    }
}
