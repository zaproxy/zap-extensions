/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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

import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.apache.commons.configuration.ConversionException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.http.HttpFieldsNames;
import org.zaproxy.zap.extension.ruleconfig.RuleConfigParam;

/**
 * a scan rule that looks for servers vulnerable to ShellShock
 *
 * @author psiinon
 */
public class ShellShockScanRule extends AbstractAppParamPlugin implements CommonActiveScanRuleInfo {
    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A06_VULN_COMP,
                    CommonAlertTag.OWASP_2017_A09_VULN_COMP,
                    CommonAlertTag.WSTG_V42_INPV_12_COMMAND_INJ);

    /** the logger object */
    private static final Logger LOGGER = LogManager.getLogger(ShellShockScanRule.class);

    /**
     * Use a standard HTTP response header, to make sure the header is not dropped by load
     * balancers, proxies, etc
     */
    private static final String ATTACK_HEADER = HttpFieldsNames.X_POWERED_BY;

    private static final String EVIDENCE = "ShellShock-Vulnerable";

    private static final String ATTACK_1 =
            "() { :;}; echo '" + ATTACK_HEADER + ": " + EVIDENCE + "'";
    // Will have sleep value concatenated on the end
    private static final String ATTACK_2 = "() { :;}; /bin/sleep ";

    private int sleep = 5;

    @Override
    public int getId() {
        return 10048;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("ascanbeta.shellshock.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("ascanbeta.shellshock.desc");
    }

    @Override
    public int getCategory() {
        return Category.SERVER;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString("ascanbeta.shellshock.soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString("ascanbeta.shellshock.ref");
    }

    @Override
    public void init() {
        // Read the sleep value from the configs
        try {
            this.sleep = this.getConfig().getInt(RuleConfigParam.RULE_COMMON_SLEEP_TIME, 5);
        } catch (ConversionException e) {
            LOGGER.debug(
                    "Invalid value for 'rules.common.sleep': {}",
                    this.getConfig().getString(RuleConfigParam.RULE_COMMON_SLEEP_TIME));
        }
        LOGGER.debug("Sleep set to {} seconds", sleep);
    }

    @Override
    public void scan(HttpMessage origMsg, String paramName, String paramValue) {
        try {
            // First try a simple reflected attack
            // With CGI, the evidence will come out in the header
            HttpMessage msg1 = getNewMsg();

            setParameter(msg1, paramName, ATTACK_1);
            sendAndReceive(msg1, false); // do not follow redirects

            List<String> ssHeaders = msg1.getResponseHeader().getHeaderValues(ATTACK_HEADER);
            if (!ssHeaders.isEmpty()) {
                for (String header : ssHeaders) {
                    if (header.contains(EVIDENCE)) {
                        buildAlert(paramName, ATTACK_1).setMessage(msg1).raise();
                        return;
                    }
                }
            }

            // Then a timing attack
            // With PHP, the evidence will come out in the body (this will be caught by the timing
            // based attack)
            boolean vulnerable = false;
            HttpMessage msg2 = getNewMsg();
            String attack = ATTACK_2 + sleep;

            setParameter(msg2, paramName, attack);
            sendAndReceive(msg2, false); // do not follow redirects
            long attackElapsedTime = msg2.getTimeElapsedMillis();

            if (attackElapsedTime > TimeUnit.SECONDS.toMillis(sleep)) {
                vulnerable = true;
                if (!Plugin.AlertThreshold.LOW.equals(this.getAlertThreshold())
                        && attackElapsedTime > TimeUnit.SECONDS.toMillis(6L)) {
                    // Could be that the server is overloaded, try a safe request
                    HttpMessage safeMsg = getNewMsg();
                    sendAndReceive(safeMsg, false); // do not follow redirects
                    if (safeMsg.getTimeElapsedMillis() > TimeUnit.SECONDS.toMillis(sleep)
                            && (safeMsg.getTimeElapsedMillis() - attackElapsedTime)
                                    < TimeUnit.SECONDS.toMillis(sleep)) {
                        // Looks like the server is just overloaded
                        vulnerable = false;
                    }
                }
            }
            if (vulnerable) {
                buildTimingAlert(paramName, attack, attackElapsedTime).setMessage(msg2).raise();
            }

        } catch (Exception e) {
            LOGGER.error("Error scanning a Host for ShellShock: {}", e.getMessage(), e);
        }
    }

    private AlertBuilder createAlert() {
        return newAlert()
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setOtherInfo(Constant.messages.getString("ascanbeta.shellshock.extrainfo"));
    }

    private AlertBuilder buildAlert(String paramName, String attack) {
        return createAlert()
                .setParam(paramName)
                .setAttack(attack)
                .setEvidence(EVIDENCE)
                .setAlertRef(getId() + "-1");
    }

    private AlertBuilder buildTimingAlert(String paramName, String attack, long attackElapsedTime) {
        return createAlert()
                .setParam(paramName)
                .setAttack(attack)
                .setEvidence(
                        Constant.messages.getString(
                                "ascanbeta.shellshock.timingbased.evidence", attackElapsedTime))
                .setAlertRef(getId() + "-2");
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public int getCweId() {
        return 78; // Improper Neutralization of Special Elements used in an OS Command ('OS Command
        // Injection')
    }

    @Override
    public int getWascId() {
        return 31; // OS Commanding
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(
                buildAlert("profile", ATTACK_1).build(),
                buildTimingAlert("profile", ATTACK_2 + "5", TimeUnit.SECONDS.toMillis(6L)).build());
    }
}
