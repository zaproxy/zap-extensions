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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerabilities;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerability;
import org.zaproxy.zap.extension.foxhound.config.FoxhoundConstants;
import org.zaproxy.zap.extension.foxhound.taint.SinkTag;
import org.zaproxy.zap.extension.foxhound.taint.SourceTag;

public class FoxhoundStoredXssCheck extends FoxhoundBaseCheck {

    private static final Vulnerability VULN = Vulnerabilities.getDefault().get("wasc_8");
    private static final Map<String, String> ALERT_TAGS;
    private static final Set<String> XSS_SINKS;
    private static final Set<String> XSS_SOURCES;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2021_A03_INJECTION,
                                CommonAlertTag.OWASP_2017_A07_XSS,
                                CommonAlertTag.WSTG_V42_INPV_02_STORED_XSS,
                                CommonAlertTag.WSTG_V42_CLNT_01_DOM_XSS));

        ALERT_TAGS = Collections.unmodifiableMap(alertTags);

        XSS_SINKS = FoxhoundConstants.getSinkNamesWithTag(SinkTag.XSS);
        XSS_SOURCES = FoxhoundConstants.getSourceNamesWithTag(SourceTag.STORAGE);
    }

    @Override
    protected Vulnerability getVulnerability() {
        return VULN;
    }

    @Override
    protected Set<String> getRequiredSourceNames() {
        return XSS_SOURCES;
    }

    @Override
    protected Set<String> getRequiredSinkNames() {
        return XSS_SINKS;
    }

    @Override
    public int getScanId() {
        return FoxhoundConstants.FOXHOUND_SCANID_STORED_XSS;
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public int getConfidence() {
        return Alert.CONFIDENCE_HIGH;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public int getCwe() {
        return 79;
    }
}
