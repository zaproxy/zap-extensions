/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrules;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import net.htmlparser.jericho.Source;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpBody;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.ResourceIdentificationUtils;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class InformationDisclosureDebugErrorsScanRule extends PluginPassiveScanner {

    private static final String MESSAGE_PREFIX = "pscanrules.informationdisclosuredebugerrors.";
    private static final int PLUGIN_ID = 10023;

    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A01_BROKEN_AC,
                    CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED,
                    CommonAlertTag.WSTG_V42_ERRH_01_ERR);

    private static final String debugErrorFile = "xml/debug-error-messages.txt";
    private static final Logger logger =
            LogManager.getLogger(InformationDisclosureDebugErrorsScanRule.class);
    private List<String> errors = null;

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        // At medium or high exclude javascript responses
        if (!AlertThreshold.LOW.equals(this.getAlertThreshold())
                && ResourceIdentificationUtils.isJavaScript(msg)) {
            return;
        }
        if (msg.getResponseBody().length() > 0 && msg.getResponseHeader().isText()) {
            String parameter;
            if ((parameter = doesResponseContainsDebugErrorMessage(msg.getResponseBody()))
                    != null) {
                this.raiseAlert(msg, id, parameter);
            }
        }
    }

    private void raiseAlert(HttpMessage msg, int id, String infoDisclosureDBError) {
        newAlert()
                .setRisk(getRisk())
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setDescription(getDescription())
                .setSolution(getSolution())
                .setEvidence(infoDisclosureDBError)
                .setCweId(getCweId())
                .setWascId(getWascId())
                .raise();
    }

    private String doesResponseContainsDebugErrorMessage(HttpBody body) {
        if (this.errors == null) {
            this.errors = loadFile(Paths.get(Constant.getZapHome(), debugErrorFile));
        }
        String sBody = body.toString().toLowerCase();
        for (String error : this.errors) {
            int start = sBody.indexOf(error);
            if (start >= 0) {
                // Return the original (case exact) string so we can match it in the response
                return body.toString().substring(start, start + error.length());
            }
        }
        return null;
    }

    private List<String> loadFile(Path path) {
        List<String> strings = new ArrayList<>();
        BufferedReader reader = null;
        File f = path.toFile();
        if (!f.exists()) {
            logger.error("No such file: {}", f.getAbsolutePath());
            return strings;
        }
        try {
            String line;
            reader = new BufferedReader(new FileReader(f));
            while ((line = reader.readLine()) != null) {
                if (!line.startsWith("#")) {
                    strings.add(line.trim().toLowerCase());
                }
            }
        } catch (IOException e) {
            logger.debug("Error on opening/reading debug error file. Error: {}", e.getMessage(), e);
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    logger.debug("Error on closing the file reader. Error: {}", e.getMessage(), e);
                }
            }
        }
        return strings;
    }

    public void setDebugErrorFile(Path path) {
        this.errors = loadFile(path);
    }

    public int getRisk() {
        return Alert.RISK_LOW;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    public int getCweId() {
        return 200; // CWE Id 200 - Information Exposure
    }

    public int getWascId() {
        return 13; // WASC Id - Info leakage
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }
}
