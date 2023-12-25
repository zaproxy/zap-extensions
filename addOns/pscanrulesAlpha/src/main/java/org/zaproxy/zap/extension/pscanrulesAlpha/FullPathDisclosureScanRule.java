/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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

import com.google.re2j.Matcher;
import com.google.re2j.Pattern;
import java.util.List;
import java.util.Map;
import net.htmlparser.jericho.Source;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class FullPathDisclosureScanRule extends PluginPassiveScanner
        implements CommonPassiveScanRuleInfo {
    private static final int PLUGIN_ID = 110009;
    private static final String MESSAGE_PREFIX = "pscanalpha.fullpathdisclosurealert.";
    private static final Logger LOGGER = LogManager.getLogger(FullPathDisclosureScanRule.class);

    // matches the following paths:
    // example for windows : C:\folder\folder
    // example for unix : /dir/dir/
    // default paths : /usr or /home etc..
    private static final Pattern PATH_PATTERN =
            Pattern.compile(
                    ("(?:/bin/|/usr/|/mnt/|/proc/|/sbin/|/dev/|/lib/|/tmp/|/opt/|/home/|/var/|/root/|/etc/|"
                            + "/Applications/|/Volumes/|/System/|/Users/|/Developer/|/Library/|"
                            + "[a-z]\\:(\\\\Program Files\\\\|\\\\Users\\\\|\\\\Windows\\\\|\\\\ProgramData\\\\|\\\\Progra~1\\\\).*)"),
                    Pattern.CASE_INSENSITIVE);
    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
                    CommonAlertTag.WSTG_V42_ERRH_01_ERR);

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        if (getHelper().isSuccess(msg)) {
            return;
        }
        String responseBody = msg.getResponseBody().toString();
        Matcher pathMatcher = PATH_PATTERN.matcher(responseBody);
        if (pathMatcher.find()) {
            String evidence = pathMatcher.group();
            LOGGER.debug("Found full path in response: {}", evidence);
            buildAlert(evidence).raise();
        }
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    private String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    private String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    private String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    private AlertBuilder buildAlert(String evidence) {
        return newAlert()
                .setConfidence(Alert.CONFIDENCE_LOW)
                .setRisk(Alert.RISK_LOW)
                .setEvidence(evidence)
                .setDescription(getDescription())
                .setSolution(getSolution())
                .setReference(getReference())
                .setSolution(getSolution())
                .setWascId(13) // WASC-13 Information Leakage
                .setCweId(209); // CWE-209: Generation of Error Message Containing Sensitive
        // Information
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(buildAlert("/home/servers/ProdServer/").build());
    }
}
