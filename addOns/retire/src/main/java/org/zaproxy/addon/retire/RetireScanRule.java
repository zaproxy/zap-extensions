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
package org.zaproxy.addon.retire;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.htmlparser.jericho.Source;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.retire.model.Repo;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class RetireScanRule extends PluginPassiveScanner {
    private static final Logger LOGGER = Logger.getLogger(RetireScanRule.class);
    private static final int PLUGIN_ID = 10003;
    private static final String COLLECTION_PATH =
            "/org/zaproxy/addon/retire/resources/jsrepository.json";

    private Repo repo;

    @Override
    public String getName() {
        return Constant.messages.getString("retire.rule.name");
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        // do nothing
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        if (!getHelper().isPage200(msg)) {
            return;
        }
        String uri = msg.getRequestHeader().getURI().toString();
        if (!msg.getResponseHeader().isImage()
                && !msg.getRequestHeader().isCss()
                && !msg.getResponseHeader().isCss()) {
            Result result = getRepo().scanJS(msg);
            if (result == null) {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("\tNo vulnerabilities found in record " + id + " with URL " + uri);
                }
            } else {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug(
                            "\tVulnerabilities found in record "
                                    + id
                                    + " with URL:"
                                    + uri
                                    + " ,name:"
                                    + ((result.getFilename() == null) ? "" : result.getFilename())
                                    + " and version:"
                                    + result.getVersion()
                                    + ", more info at:"
                                    + result.getInfo());
                }

                String otherInfo = getDetails(Result.CVE, result.getInfo());

                if (result.hasOtherInfo()) {
                    otherInfo = otherInfo + result.getOtherinfo();
                }

                buildAlert(result, otherInfo).raise();
            }
        }
    }

    private AlertBuilder buildAlert(Result result, String otherInfo) {
        return newAlert()
                .setRisk(Alert.RISK_MEDIUM)
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setDescription(
                        Constant.messages.getString(
                                "retire.rule.desc", result.getFilename(), result.getVersion()))
                .setOtherInfo(otherInfo)
                .setReference(getDetails(Result.INFO, result.getInfo()))
                .setSolution(Constant.messages.getString("retire.rule.soln", result.getFilename()))
                .setEvidence(result.getEvidence())
                .setCweId(829); // CWE-829: Inclusion of Functionality from Untrusted Control Sphere
    }

    @Override
    public List<Alert> getExampleAlerts() {
        List<Alert> alerts = new ArrayList<Alert>();
        alerts.add(
                buildAlert(new Result("ExampleLibrary", "x.y.z", Collections.emptyMap(), null), "")
                        .build());
        return alerts;
    }

    private String getDetails(String key, Map<String, Set<String>> info) {
        if (info.isEmpty() || !info.containsKey(key)) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (String item : info.get(key)) {
            sb.append(item).append('\n');
        }
        return sb.toString();
    }

    @Override
    public void setParent(PassiveScanThread parent) {
        // Nothing to do.
    }

    private Repo getRepo() {
        if (repo == null) {
            try {
                this.repo = new Repo(COLLECTION_PATH);
            } catch (IOException e) {
                LOGGER.warn("Failed to open the Retire.js collection JSON file.", e);
            }
        }
        return repo;
    }

    // This method supports unit tests
    void setRepo(Repo repo) {
        this.repo = repo;
    }
}
