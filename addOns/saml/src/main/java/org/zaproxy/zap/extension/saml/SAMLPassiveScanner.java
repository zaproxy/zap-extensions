/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.saml;

import net.htmlparser.jericho.Source;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class SAMLPassiveScanner extends PluginPassiveScanner {

    private static final String NAME = Constant.messages.getString("saml.passivescanner.name");
    private static final String DESCRIPTION =
            Constant.messages.getString("saml.passivescanner.desc");
    private static final String OTHER_INFO =
            Constant.messages.getString("saml.passivescanner.otherinfo");
    private static final String REFS = Constant.messages.getString("saml.passivescanner.refs");

    private PassiveScanThread parent;

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        scanMessage(msg, id);
    }

    private void scanMessage(HttpMessage msg, int id) {
        SAMLInspectionResult samlInspectionResult = SAMLUtils.inspectMessage(msg);
        if (samlInspectionResult.hasSAMLMessage()) {
            parent.addTag("SAML");
            raiseAlert(samlInspectionResult);
        }
    }

    private void raiseAlert(SAMLInspectionResult samlInspectionResult) {
        newAlert()
                .setRisk(Alert.RISK_INFO)
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setDescription(DESCRIPTION)
                .setOtherInfo(OTHER_INFO)
                .setReference(REFS)
                .setParam(samlInspectionResult.getEvidence().getName())
                .setEvidence(samlInspectionResult.getEvidence().getValue())
                .raise();
    }

    @Override
    public int getPluginId() {
        return 10070;
    }

    @Override
    public String getName() {
        return NAME;
    }
}
