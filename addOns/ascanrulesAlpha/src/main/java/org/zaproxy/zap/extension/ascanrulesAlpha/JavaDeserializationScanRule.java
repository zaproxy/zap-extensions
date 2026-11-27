/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrulesAlpha;

import java.util.Collections;
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
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.addon.oast.ExtensionOast;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

/**
 * Replaces Base64 encoded Java serialized objects with one that makes the target resolve an OAST
 * host name when deserialized, and raises an alert when that interaction is received.
 */
public class JavaDeserializationScanRule extends AbstractAppParamPlugin
        implements CommonActiveScanRuleInfo {

    private static final Logger LOGGER = LogManager.getLogger(JavaDeserializationScanRule.class);
    private static final String PREFIX = "ascanalpha.javadeserialization.";
    private static final String JSO_BASE_64_MAGIC_SEQUENCE = "rO0AB";
    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2025_A08_INTEGRITY_FAIL,
                                CommonAlertTag.OWASP_2021_A08_INTEGRITY_FAIL,
                                CommonAlertTag.OWASP_2017_A08_INSECURE_DESERIAL));
        alertTags.put(ExtensionOast.OAST_ALERT_TAG_KEY, ExtensionOast.OAST_ALERT_TAG_VALUE);
        alertTags.put(PolicyTag.QA_FULL.getTag(), "");
        alertTags.put(PolicyTag.PENTEST.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    @Override
    public int getId() {
        return 40050;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(PREFIX + "name");
    }

    @Override
    public boolean targets(TechSet technologies) {
        return technologies.includesAny(Tech.JAVA);
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(PREFIX + "desc");
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString(PREFIX + "soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(PREFIX + "refs");
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public int getCweId() {
        return 502; // CWE-502: Deserialization of Untrusted Data
    }

    @Override
    public int getWascId() {
        return 20; // WASC-20: Improper Input Handling
    }

    @Override
    public void init() {
        ExtensionOast extOast =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionOast.class);
        if (extOast == null || extOast.getActiveScanOastService() == null) {
            getParent().pluginSkipped(this, Constant.messages.getString(PREFIX + "skipped"));
        }
    }

    @Override
    public void scan(HttpMessage msg, String param, String value) {
        if (value == null || !value.startsWith(JSO_BASE_64_MAGIC_SEQUENCE)) {
            return;
        }
        ExtensionOast extOast =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionOast.class);
        try {
            HttpMessage testMsg = getNewMsg();
            Alert alert = createAlert().setParam(param).setMessage(testMsg).build();
            String host = extOast.registerAlertAndGetPayload(alert);
            String attack =
                    JavaSerializedPayload.encodeLike(value, JavaSerializedPayload.create(host));
            alert.setAttack(attack);
            setParameter(testMsg, param, attack);
            sendAndReceive(testMsg);
        } catch (Exception e) {
            LOGGER.warn(e.getMessage(), e);
        }
    }

    private AlertBuilder createAlert() {
        return newAlert().setConfidence(Alert.CONFIDENCE_MEDIUM);
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(createAlert().build());
    }
}
