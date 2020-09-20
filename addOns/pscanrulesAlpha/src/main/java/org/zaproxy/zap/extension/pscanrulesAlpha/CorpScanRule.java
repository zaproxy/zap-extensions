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

import java.util.ArrayList;
import java.util.List;
import net.htmlparser.jericho.Source;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * Cross-Origin-Resource-Policy Scan Rule
 *
 * @see <a
 *     href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Cross-Origin_Resource_Policy_(CORP)">CORP
 *     on MDN</a>
 */
public class CorpScanRule extends PluginPassiveScanner {
    /** Prefix for internationalized messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanalpha.corp.";

    private static final int PLUGIN_ID = 90004;
    public static final String CROSS_ORIGIN_RESOURCE_POLICY_HEADER = "Cross-Origin-Resource-Policy";

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        List<String> corpHeaders =
                msg.getResponseHeader()
                        .getHeaderValues(CorpScanRule.CROSS_ORIGIN_RESOURCE_POLICY_HEADER);
        if (corpHeaders.isEmpty()) {
            corpHeaderAlert("").raise();
        }
        for (String corpHeader : corpHeaders) {
            if ("same-site".equalsIgnoreCase(corpHeader)
                    || !("same-origin".equalsIgnoreCase(corpHeader)
                            || "cross-origin".equalsIgnoreCase(corpHeader))) {
                corpHeaderAlert(corpHeader).raise();
            }
        }
    }

    @Override
    public void setParent(PassiveScanThread parent) {
        // Nothing to do.
    }

    @Override
    public String getName() {
        return getString("name");
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    private String getString(String param) {
        return Constant.messages.getString(MESSAGE_PREFIX + param);
    }

    private AlertBuilder corpHeaderAlert(String evidence) {
        return newAlert()
                .setRisk(Alert.RISK_LOW)
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setParam(CROSS_ORIGIN_RESOURCE_POLICY_HEADER)
                .setDescription(getString("desc"))
                .setSolution(getString("soln"))
                .setReference(getString("refs"))
                .setCweId(16) // CWE-16: Configuration
                .setWascId(14) // WASC-14: Server Misconfiguration
                .setEvidence(evidence);
    }

    public List<Alert> getExampleAlerts() {
        List<Alert> alerts = new ArrayList<Alert>();
        alerts.add(corpHeaderAlert("").build());
        return alerts;
    }
}
