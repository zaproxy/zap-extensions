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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import net.htmlparser.jericho.Source;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.network.HttpBody;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * An example passive scan rule, for more details see
 * https://www.zaproxy.org/blog/2014-04-03-hacking-zap-3-passive-scan-rules/
 *
 * @author psiinon
 */
public class ExampleFilePassiveScanRule extends PluginPassiveScanner {

    /** Prefix for internationalized messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanalpha.examplefile.";

    private static final String examplePscanFile = "txt/example-pscan-file.txt";
    private static final Logger LOGGER = LogManager.getLogger(ExampleFilePassiveScanRule.class);
    private List<String> strings = null;

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        // Only checking the response for this example
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        if (!Constant.isDevBuild()) {
            // Only run this example scan rule in dev mode
            // Uncomment locally if you want to see these alerts in non dev mode ;)
            return;
        }
        if (msg.getResponseBody().length() > 0 && msg.getResponseHeader().isText()) {
            String parameter;
            if ((parameter = doesResponseContainString(msg.getResponseBody())) != null) {
                this.createAlert(parameter).raise();
            }
        }
    }

    private AlertBuilder createAlert(String evidence) {
        return newAlert()
                .setRisk(Alert.RISK_LOW)
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setDescription(Constant.messages.getString(MESSAGE_PREFIX + "desc"))
                .setOtherInfo(Constant.messages.getString(MESSAGE_PREFIX + "other"))
                .setSolution(Constant.messages.getString(MESSAGE_PREFIX + "soln"))
                .setReference(Constant.messages.getString(MESSAGE_PREFIX + "refs"))
                .setEvidence(evidence)
                .setWascId(13);
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(createAlert("").build());
    }

    private String doesResponseContainString(HttpBody body) {
        if (this.strings == null) {
            this.strings = loadFile(examplePscanFile);
        }
        String sBody;
        if (Plugin.AlertThreshold.HIGH.equals(this.getAlertThreshold())) {
            // For a high threshold perform a case exact check
            sBody = body.toString();
        } else {
            // For all other thresholds perform a case ignore check
            sBody = body.toString().toLowerCase();
        }

        for (String str : this.strings) {
            if (!Plugin.AlertThreshold.HIGH.equals(this.getAlertThreshold())) {
                // Use case ignore unless a high threshold has been specified
                str = str.toLowerCase();
            }
            int start = sBody.indexOf(str);
            if (start >= 0) {
                // Return the original (case exact) string so we can match it in the response
                return body.toString().substring(start, start + str.length());
            }
        }
        return null;
    }

    private static List<String> loadFile(String file) {
        /*
         * ZAP will have already extracted the file from the add-on and put it underneath the 'ZAP home' directory
         */
        List<String> strings = new ArrayList<>();
        BufferedReader reader = null;
        File f = new File(Constant.getZapHome() + File.separator + file);
        if (!f.exists()) {
            LOGGER.error("No such file: {}", f.getAbsolutePath());
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
            LOGGER.error(
                    "Error on opening/reading example error file. Error: {}", e.getMessage(), e);
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    LOGGER.debug("Error on closing the file reader. Error: {}", e.getMessage(), e);
                }
            }
        }
        return strings;
    }

    @Override
    public int getPluginId() {
        /*
         * This should be unique across all active and passive rules.
         * The master list is https://github.com/zaproxy/zaproxy/blob/main/docs/scanners.md
         */
        return 60001;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }
}
