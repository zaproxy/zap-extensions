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
package org.zaproxy.zap.extension.ascanrulesAlpha;

import java.io.IOException;
import java.util.List;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerabilities;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerability;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

/**
 * An example active scan rule, for more details see
 * https://www.zaproxy.org/blog/2014-04-30-hacking-zap-4-active-scan-rules/
 *
 * @author psiinon
 */
public class ExampleSimpleActiveScanRule extends AbstractAppParamPlugin
        implements CommonActiveScanRuleInfo {

    // wasc_10 is Denial of Service - well, its just an example ;)
    private static final Vulnerability VULN = Vulnerabilities.getDefault().get("wasc_10");

    private Random rnd = new Random();

    private static final Logger LOGGER = LogManager.getLogger(ExampleSimpleActiveScanRule.class);

    @Override
    public int getId() {
        /*
         * This should be unique across all active and passive rules.
         * The master list is https://github.com/zaproxy/zaproxy/blob/main/docs/scanners.md
         */
        return 60100;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("ascanalpha.examplesimple.name");
    }

    @Override
    public boolean targets(
            TechSet technologies) { // This method allows the programmer or user to restrict when a
        // scanner is run based on the technologies selected.  For example, to restrict the scanner
        // to run just when
        // C language is selected
        return technologies.includes(Tech.C);
    }

    @Override
    public String getDescription() {
        return VULN.getDescription();
    }

    @Override
    public int getCategory() {
        return Category.MISC;
    }

    @Override
    public String getSolution() {
        return VULN.getSolution();
    }

    @Override
    public String getReference() {
        return VULN.getReferencesAsString();
    }

    /*
     * This method is called by the active scanner for each GET and POST parameter for every page
     * @see org.parosproxy.paros.core.scanner.AbstractAppParamPlugin#scan(org.parosproxy.paros.network.HttpMessage, java.lang.String, java.lang.String)
     */
    @Override
    public void scan(HttpMessage msg, String param, String value) {
        try {
            if (!Constant.isDevBuild()) {
                // Only run this example scan rule in dev mode
                // Uncomment locally if you want to see these alerts in non dev mode ;)
                return;
            }
            // This is where you change the 'good' request to attack the application
            // You can make multiple requests if needed
            String attack = "attack";

            // Always use getNewMsg() for each new request
            HttpMessage testMsg = getNewMsg();
            setParameter(testMsg, param, attack);
            sendAndReceive(testMsg);

            // This is where you detect potential vulnerabilities in the response

            // For this example we're just going to raise the alert at random!

            if (rnd.nextInt(10) == 0) {
                createAlert(param, attack).setMessage(testMsg).raise();
                return;
            }

        } catch (IOException e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    private AlertBuilder createAlert(String param, String attack) {
        return newAlert().setConfidence(Alert.CONFIDENCE_MEDIUM).setParam(param).setAttack(attack);
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public int getCweId() {
        // The CWE id
        return 0;
    }

    @Override
    public int getWascId() {
        // The WASC ID
        return 0;
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(createAlert("foo", "attack").build());
    }
}
