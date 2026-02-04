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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.htmlparser.jericho.Source;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.addon.retire.model.Repo;
import org.zaproxy.addon.retire.model.Repo.VulnerabilityData;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class RetireScanRule extends PluginPassiveScanner {
    private static final Logger LOGGER = LogManager.getLogger(RetireScanRule.class);
    private static final int PLUGIN_ID = 10003;
    private static final String COLLECTION_PATH =
            "/org/zaproxy/addon/retire/resources/jsrepository.json";
    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2021_A06_VULN_COMP,
                                CommonAlertTag.OWASP_2017_A09_VULN_COMP));
        alertTags.put(PolicyTag.PENTEST.getTag(), "");
        alertTags.put(PolicyTag.DEV_STD.getTag(), "");
        alertTags.put(PolicyTag.QA_STD.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    private Repo repo;

    /**
     * Constructs a {@code RetireScanRule} with the given {@code Repo}.
     *
     * @param repo the {@link Repo} instance
     */
    public RetireScanRule(Repo repo) {
        this.repo = repo;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("retire.rule.name");
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    public String getHelpLink() {
        return "https://www.zaproxy.org/docs/desktop/addons/retire.js/#id-" + PLUGIN_ID;
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        Repo scanRepo = getRepo();
        if (!getHelper().isPage200(msg) || scanRepo == null) {
            return;
        }
        String uri = msg.getRequestHeader().getURI().toString();
        if (msg.getResponseHeader().isHtml() || msg.getResponseHeader().isJavaScript()) {
            Result result = scanRepo.scanJS(msg, source);
            if (result == null) {
                LOGGER.debug("\tNo vulnerabilities found in record {} with URL {}", id, uri);
            } else {
                LOGGER.debug(
                        "\tVulnerabilities found in record {} with URL: {}, name: {} and version: {}, more info at: {}",
                        id,
                        uri,
                        (result.getFilename() == null) ? "" : result.getFilename(),
                        result.getVersion(),
                        result.getInformation());

                StringBuilder otherInfo =
                        new StringBuilder(getOtherInfo(result.getFilename(), result.getVersion()))
                                .append(getDetails(result.getInformation().getCves()));
                if (result.hasOtherInfo()) {
                    otherInfo.append(result.getOtherinfo()).append('\n');
                }
                otherInfo.append(getDetails(result.getInformation().getInfo()));

                buildAlert(result, otherInfo.toString()).raise();
            }
        }
    }

    private static String getOtherInfo(String fileName, String version) {
        return Constant.messages.getString("retire.rule.otherinfo", fileName, version);
    }

    private AlertBuilder buildAlert(Result result, String otherInfo) {
        return newAlert()
                .setRisk(result.getInformation().getRisk())
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setName(getAlertName())
                .setDescription(Constant.messages.getString("retire.rule.desc"))
                .setOtherInfo(otherInfo)
                .setTags(getAllAlertTags(result))
                .setReference(Constant.messages.getString("retire.rule.references"))
                .setSolution(Constant.messages.getString("retire.rule.soln"))
                .setEvidence(result.getEvidence().trim())
                .setCweId(1395); // CWE-1395: Dependency on Vulnerable Third-Party Component
    }

    @Override
    public List<Alert> getExampleAlerts() {
        List<Alert> alerts = new ArrayList<>();
        String file = "ExampleLibrary.js";
        String version = "13.3.7";
        alerts.add(
                buildAlert(
                                new Result(file, version, VulnerabilityData.EMPTY, version),
                                getOtherInfo(file, version))
                        .build());
        return alerts;
    }

    @Override
    public PluginPassiveScanner copy() {
        RetireScanRule scanRule = new RetireScanRule(this.repo);
        scanRule.setConfig(this.getConfig());
        return scanRule;
    }

    private static String getAlertName() {
        return Constant.messages.getString("retire.alert.name");
    }

    private static String getDetails(Set<String> info) {
        if (info.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (String item : info) {
            sb.append(item).append('\n');
        }
        return sb.toString();
    }

    private Map<String, String> getAllAlertTags(Result result) {
        Map<String, String> alertTags = new HashMap<>();
        result.getCves().forEach(value -> CommonAlertTag.putCve(alertTags, value));
        alertTags.putAll(getAlertTags());
        return alertTags;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    protected Repo getRepo() {
        return repo;
    }
}
