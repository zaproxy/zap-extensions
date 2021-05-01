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
import net.htmlparser.jericho.Source;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * a scan rule to passively scan for the presence of the X-AspNet-Version/X-AspNetMvc-Version
 * response header
 */
public class XAspNetVersionScanRule extends PluginPassiveScanner {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanrules.xaspnetversion.";

    private final List<String> xAspNetHeaders = new ArrayList<String>();

    public XAspNetVersionScanRule() {
        xAspNetHeaders.add("X-AspNet-Version");
        xAspNetHeaders.add("X-AspNetMvc-Version");
    }

    @Override
    public void setParent(PassiveScanThread parent) {
        // Nothing to do.
    }

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {}

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        for (String header : xAspNetHeaders) {
            List<String> found = msg.getResponseHeader().getHeaderValues(header);

            if (!found.isEmpty()) {
                this.raiseAlert(msg, id, found.get(0));
            }
        }
    }

    private void raiseAlert(HttpMessage msg, int id, String evidence) {
        newAlert()
                .setRisk(Alert.RISK_LOW)
                .setConfidence(Alert.CONFIDENCE_HIGH)
                .setDescription(Constant.messages.getString(MESSAGE_PREFIX + "desc"))
                .setOtherInfo(Constant.messages.getString(MESSAGE_PREFIX + "extrainfo"))
                .setSolution(Constant.messages.getString(MESSAGE_PREFIX + "soln"))
                .setReference(Constant.messages.getString(MESSAGE_PREFIX + "refs"))
                .setEvidence(evidence)
                .setCweId(933) // CWE-933: OWASP Top Ten 2013 Category A5 - Security
                // Misconfiguration
                .setWascId(14) // WASC-14: Server Misconfiguration
                .raise();
    }

    @Override
    public int getPluginId() {
        return 10061;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }
}
