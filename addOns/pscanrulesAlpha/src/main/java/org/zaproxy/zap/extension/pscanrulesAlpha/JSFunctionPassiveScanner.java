/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/** Passive Scan Rule for Dangerous JS Functions https://github.com/zaproxy/zaproxy/issues/5673 */
public class JSFunctionPassiveScanner extends PluginPassiveScanner {

    /** Prefix for internationalized messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanalpha.jsfunction.";

    private static final String FUNC_LIST = "xml/js-function-list.txt";
    private static final Logger LOGGER = Logger.getLogger(JSFunctionPassiveScanner.class);
    private static final int PLUGIN_ID = 10110;

    private PassiveScanThread parent = null;
    private List<String> functions = null;

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        // This rule only scans responses received
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        if (this.functions == null) {
            this.functions = loadFunctions();
        }
        String content = source.toString();

        for (String func : this.functions) {
            if (content.toLowerCase().contains(func.toLowerCase())) {
                raiseAlert(msg, id, content);
            }
        }
    }

    private void raiseAlert(HttpMessage msg, int id, String evidence) {
        Alert alert =
                new Alert(getPluginId(), Alert.RISK_MEDIUM, Alert.CONFIDENCE_MEDIUM, getName());
        alert.setDetail(
                this.getDescription(),
                msg.getRequestHeader().getURI().toString(),
                "", // Param, not relevant for this example vulnerability
                "", // Attack, not relevant for passive vulnerabilities
                this.getOtherInfo(),
                this.getSolution(),
                this.getReference(),
                evidence, // Evidence
                0, // CWE Id - return 0 if no relevant one
                0, // WASC Id - Info leakage (return 0 if no relevant one)
                msg);

        parent.raiseAlert(id, alert);
    }

    private List<String> loadFunctions() {
        List<String> strings = new ArrayList<String>();
        BufferedReader reader = null;
        File f = new File(Constant.getZapHome() + File.separator + FUNC_LIST);
        if (!f.exists()) {
            LOGGER.error("No such file: " + f.getAbsolutePath());
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
                    "Error on opening/reading example error file. Error: " + e.getMessage(), e);
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    LOGGER.debug("Error on closing the file reader. Error: " + e.getMessage(), e);
                }
            }
        }
        return strings;
    }

    @Override
    public void setParent(PassiveScanThread parent) {
        this.parent = parent;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    private String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    private String getOtherInfo() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    private String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    private String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }
}
