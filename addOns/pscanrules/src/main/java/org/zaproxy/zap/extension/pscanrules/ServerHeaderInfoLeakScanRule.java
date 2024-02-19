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
package org.zaproxy.zap.extension.pscanrules;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import net.htmlparser.jericho.Source;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * Server Header Version Information Leak passive scan rule
 * https://github.com/zaproxy/zaproxy/issues/1169
 */
public class ServerHeaderInfoLeakScanRule extends PluginPassiveScanner
        implements CommonPassiveScanRuleInfo {

    private static final int PLUGIN_ID = 10036;

    private static final Logger LOGGER = LogManager.getLogger(ServerHeaderInfoLeakScanRule.class);

    private static final Pattern VERSION_PATTERN = Pattern.compile(".*\\d.*");
    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
                    CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG,
                    CommonAlertTag.WSTG_V42_INFO_02_FINGERPRINT_WEB_SERVER);

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        long start = System.currentTimeMillis();

        List<String> serverOption = msg.getResponseHeader().getHeaderValues("Server");
        if (!serverOption.isEmpty()) { // Header Found
            // It is set so lets check it. Should only be one but it's a vector so iterate to be
            // sure.
            for (String serverDirective : serverOption) {
                boolean matched = VERSION_PATTERN.matcher(serverDirective).matches();
                if (matched) { // See if there's any version info.
                    // While an alpha string might be the server type (Apache, Netscape, IIS, etc.)
                    // that's much less of a head-start than actual version details.
                    buildVersionLeakAlert(serverDirective).raise();
                } else if (Plugin.AlertThreshold.LOW.equals(this.getAlertThreshold())) {
                    buildHeaderPresentAlert(serverDirective).raise();
                }
            }
        }
        LOGGER.debug("\tScan of record {} took {}ms", id, System.currentTimeMillis() - start);
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("pscanrules.serverheader.rule.name");
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public List<Alert> getExampleAlerts() {
        List<Alert> alerts = new ArrayList<>();
        alerts.add(buildHeaderPresentAlert("Apache").build());
        alerts.add(buildVersionLeakAlert("Apache/2.4.1 (Unix)").build());
        return alerts;
    }

    private AlertBuilder createAlert(String directive) {
        return newAlert()
                .setConfidence(Alert.CONFIDENCE_HIGH)
                .setSolution(
                        Constant.messages.getString("pscanrules.serverheaderinfoleak.general.soln"))
                .setReference(
                        Constant.messages.getString("pscanrules.serverheaderinfoleak.general.refs"))
                .setEvidence(directive)
                .setCweId(200)
                .setWascId(13);
    }

    private AlertBuilder buildHeaderPresentAlert(String directive) {
        return createAlert(directive)
                .setRisk(Alert.RISK_INFO)
                .setName(Constant.messages.getString("pscanrules.serverheaderinfoleak.name"))
                .setDescription(
                        Constant.messages.getString("pscanrules.serverheaderinfoleak.desc"));
    }

    private AlertBuilder buildVersionLeakAlert(String directive) {
        return createAlert(directive)
                .setRisk(Alert.RISK_LOW)
                .setName(Constant.messages.getString("pscanrules.serverheaderversioninfoleak.name"))
                .setDescription(
                        Constant.messages.getString("pscanrules.serverheaderversioninfoleak.desc"));
    }
}
