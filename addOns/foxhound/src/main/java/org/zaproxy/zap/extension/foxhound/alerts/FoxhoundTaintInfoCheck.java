/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.zap.extension.foxhound.alerts;

import java.util.Map;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.zap.extension.foxhound.config.FoxhoundConstants;
import org.zaproxy.zap.extension.foxhound.taint.TaintInfo;

public class FoxhoundTaintInfoCheck implements FoxhoundVulnerabilityCheck {

    @Override
    public int getScanId() {
        return FoxhoundConstants.FOXHOUND_SCANID_DATAFLOW;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return Map.of();
    }

    @Override
    public String getVulnName() {
        return "Client-Side Data Flow";
    }

    @Override
    public int getRisk() {
        return Alert.RISK_INFO;
    }

    @Override
    public int getConfidence() {
        return Alert.CONFIDENCE_HIGH;
    }

    @Override
    public String getDescription() {
        return "An interesting data-flow was found in client-side JavaScript";
    }

    @Override
    public String getSolution() {
        return "";
    }

    @Override
    public String getReferences() {
        return "";
    }

    @Override
    public int getCwe() {
        return 0;
    }

    @Override
    public int getWascId() {
        return 0;
    }

    @Override
    public boolean shouldAlert(TaintInfo taint) {
        return true;
    }
}
