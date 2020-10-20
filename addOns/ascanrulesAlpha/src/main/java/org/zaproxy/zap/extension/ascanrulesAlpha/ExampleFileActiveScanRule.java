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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.network.HttpBody;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

/**
 * An example active scan rule, for more details see
 * https://www.zaproxy.org/blog/2014-04-30-hacking-zap-4-active-scan-rules/
 *
 * @author psiinon
 */
public class ExampleFileActiveScanRule extends AbstractAppParamPlugin {

    /** Prefix for internationalized messages used by this rule */
    private static final String MESSAGE_PREFIX = "ascanalpha.examplefile.";

    private static final String exampleAscanFile = "txt/example-ascan-file.txt";
    private List<String> strings = null;
    private static Logger log = Logger.getLogger(ExampleFileActiveScanRule.class);

    @Override
    public int getId() {
        /*
         * This should be unique across all active and passive rules.
         * The master list is https://github.com/zaproxy/zaproxy/blob/develop/docs/scanners.md
         */
        return 60101;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
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
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    private String getOtherInfo() {
        return Constant.messages.getString(MESSAGE_PREFIX + "other");
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    @Override
    public int getCategory() {
        return Category.MISC;
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

            if (this.strings == null) {
                this.strings = loadFile(exampleAscanFile);
            }
            // This is where you change the 'good' request to attack the application
            // You can make multiple requests if needed
            int numAttacks = 0;

            switch (this.getAttackStrength()) {
                case LOW:
                    numAttacks = 6;
                    break;
                case MEDIUM:
                    numAttacks = 12;
                    break;
                case HIGH:
                    numAttacks = 24;
                    break;
                case INSANE:
                    numAttacks = 96;
                    break;
                default:
                    break;
            }

            for (int i = 0; i < numAttacks; i++) {
                if (this.isStop()) {
                    // User has stopped the scan
                    break;
                }
                if (i >= this.strings.size()) {
                    // run out of attack strings
                    break;
                }
                String attack = this.strings.get(i);
                // Always use getNewMsg() for each new request
                HttpMessage testMsg = getNewMsg();
                setParameter(testMsg, param, attack);
                sendAndReceive(testMsg);

                // This is where you detect potential vulnerabilities in the response
                String evidence;
                if ((evidence = doesResponseContainString(msg.getResponseBody(), attack)) != null) {
                    // Raise an alert
                    newAlert()
                            .setConfidence(Alert.CONFIDENCE_MEDIUM)
                            .setParam(param)
                            .setAttack(attack)
                            .setOtherInfo(getOtherInfo())
                            .setEvidence(evidence)
                            .setMessage(testMsg)
                            .raise();
                    return;
                }
            }

        } catch (IOException e) {
            log.error(e.getMessage(), e);
        }
    }

    private String doesResponseContainString(HttpBody body, String str) {
        String sBody;
        if (Plugin.AlertThreshold.HIGH.equals(this.getAlertThreshold())) {
            // For a high threshold perform a case exact check
            sBody = body.toString();
        } else {
            // For all other thresholds perform a case ignore check
            sBody = body.toString().toLowerCase();
        }

        if (!Plugin.AlertThreshold.HIGH.equals(this.getAlertThreshold())) {
            // Use case ignore unless a high threshold has been specified
            str = str.toLowerCase();
        }
        int start = sBody.indexOf(str);
        if (start >= 0) {
            // Return the original (case exact) string so we can match it in the response
            return body.toString().substring(start, start + str.length());
        }
        return null;
    }

    private List<String> loadFile(String file) {
        /*
         * ZAP will have already extracted the file from the add-on and put it underneath the 'ZAP home' directory
         */
        List<String> strings = new ArrayList<String>();
        BufferedReader reader = null;
        File f = new File(Constant.getZapHome() + File.separator + file);
        if (!f.exists()) {
            log.error("No such file: " + f.getAbsolutePath());
            return strings;
        }
        try {
            String line;
            reader = new BufferedReader(new FileReader(f));
            while ((line = reader.readLine()) != null) {
                if (!line.startsWith("#") && line.length() > 0) {
                    strings.add(line);
                }
            }
        } catch (IOException e) {
            log.error("Error on opening/reading example error file. Error: " + e.getMessage(), e);
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    log.debug("Error on closing the file reader. Error: " + e.getMessage(), e);
                }
            }
        }
        return strings;
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
