/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
import net.htmlparser.jericho.Source;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * a scan rule to passively scan for the presence of the X-AspNet-Version/X-AspNetMvc-Version
 * response header
 */
public class XAspNetVersionScanRule extends PluginPassiveScanner
        implements CommonPassiveScanRuleInfo {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanrules.xaspnetversion.";

    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
                    CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG,
                    CommonAlertTag.WSTG_V42_INFO_08_FINGERPRINT_APP_FRAMEWORK);

    private final List<String> xAspNetHeaders = new ArrayList<>();

    public XAspNetVersionScanRule() {
        xAspNetHeaders.add("X-AspNet-Version");
        xAspNetHeaders.add("X-AspNetMvc-Version");
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        for (String header : xAspNetHeaders) {
            List<String> found = msg.getResponseHeader().getHeaderValues(header);

            if (!found.isEmpty()) {
                createAlert(found.get(0)).raise();
            }
        }
    }

    private AlertBuilder createAlert(String evidence) {
        return newAlert()
                .setRisk(getRisk())
                .setConfidence(Alert.CONFIDENCE_HIGH)
                .setDescription(Constant.messages.getString(MESSAGE_PREFIX + "desc"))
                .setOtherInfo(Constant.messages.getString(MESSAGE_PREFIX + "extrainfo"))
                .setSolution(Constant.messages.getString(MESSAGE_PREFIX + "soln"))
                .setReference(Constant.messages.getString(MESSAGE_PREFIX + "refs"))
                .setEvidence(evidence)
                .setCweId(getCweId())
                .setWascId(getWascId());
    }

    @Override
    public int getPluginId() {
        return 10061;
    }

    public int getRisk() {
        return Alert.RISK_LOW;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    public int getCweId() {
        return 933; // CWE-933: OWASP Top Ten 2013 Category A5 - Security Misconfiguration
    }

    public int getWascId() {
        return 14; //  WASC-14: Server Misconfiguration
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(createAlert("1/1.1").build());
    }
}
