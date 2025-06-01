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
package org.zaproxy.zap.extension.pscanrulesAlpha;

import java.util.List;
import java.util.Random;
import net.htmlparser.jericho.Source;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerabilities;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerability;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * An example passive scan rule, for more details see
 * https://www.zaproxy.org/blog/2014-04-03-hacking-zap-3-passive-scan-rules/
 *
 * @author psiinon
 */
public class ExampleSimplePassiveScanRule extends PluginPassiveScanner {

    // wasc_10 is Denial of Service - well, its just an example ;)
    private static final Vulnerability VULN = Vulnerabilities.getDefault().get("wasc_10");
    private static final Logger LOGGER = LogManager.getLogger(ExampleSimplePassiveScanRule.class);

    private Random rnd = new Random();

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        // You can also detect potential vulnerabilities here, with the same caveats as below.
    }

    @Override
    public int getPluginId() {
        /*
         * This should be unique across all active and passive rules.
         * The master list is https://github.com/zaproxy/zaproxy/blob/main/docs/scanners.md
         */
        return 60000;
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        if (!Constant.isDevBuild()) {
            // Only run this example scan rule in dev mode
            // Uncomment locally if you want to see these alerts in non dev mode ;)
            return;
        }
        long start = System.currentTimeMillis();

        // This is where you detect potential vulnerabilities.
        // You can examine the msg or source but should not change anything
        // or make any requests to the server

        // For this example we're just going to raise the alert at random!

        if (rnd.nextInt(10) == 0) {
            createAlert().raise();
        }

        LOGGER.debug("\tScan of record {} took {} ms", id, System.currentTimeMillis() - start);
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(createAlert().build());
    }

    private AlertBuilder createAlert() {
        return newAlert()
                .setRisk(Alert.RISK_MEDIUM)
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setDescription(getDescription())
                .setSolution(getSolution())
                .setReference(getReference());
    }

    @Override
    public String getName() {
        // Strip off the "Example Passive Scan Rule: " part if implementing a real one ;)
        return "Example Passive Scan Rule: " + VULN.getName();
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
}
