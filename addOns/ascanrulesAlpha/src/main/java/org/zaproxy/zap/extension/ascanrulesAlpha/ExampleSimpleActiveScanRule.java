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
import java.util.Random;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

/**
 * An example active scan rule, for more details see
 * https://www.zaproxy.org/blog/2014-04-30-hacking-zap-4-active-scan-rules/
 *
 * @author psiinon
 */
public class ExampleSimpleActiveScanRule extends AbstractAppParamPlugin {

    // wasc_10 is Denial of Service - well, its just an example ;)
    private static Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_10");

    private Random rnd = new Random();

    private static Logger log = Logger.getLogger(ExampleSimpleActiveScanRule.class);

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
        // Strip off the "Example Active Scan Rule: " part if implementing a real one ;)
        if (vuln != null) {
            return "Example Active Scan Rule: " + vuln.getAlert();
        }
        return "Example Active Scan Rule: Denial of Service";
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
        if (vuln != null) {
            return vuln.getDescription();
        }
        return "Failed to load vulnerability description from file";
    }

    @Override
    public int getCategory() {
        return Category.MISC;
    }

    @Override
    public String getSolution() {
        if (vuln != null) {
            return vuln.getSolution();
        }
        return "Failed to load vulnerability solution from file";
    }

    @Override
    public String getReference() {
        if (vuln != null) {
            StringBuilder sb = new StringBuilder();
            for (String ref : vuln.getReferences()) {
                if (sb.length() > 0) {
                    sb.append("\n");
                }
                sb.append(ref);
            }
            return sb.toString();
        }
        return "Failed to load vulnerability reference from file";
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
                newAlert()
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setParam(param)
                        .setAttack(value)
                        .setMessage(testMsg)
                        .raise();
                return;
            }

        } catch (IOException e) {
            log.error(e.getMessage(), e);
        }
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
}
