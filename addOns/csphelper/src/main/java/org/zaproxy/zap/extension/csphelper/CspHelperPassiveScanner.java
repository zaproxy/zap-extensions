/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.zap.extension.csphelper;

import net.htmlparser.jericho.Source;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PassiveScanner;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class CspHelperPassiveScanner implements PassiveScanner {

    private final CspHelper cspHelper;

    public CspHelperPassiveScanner(CspHelper cspHelper) {
        this.cspHelper = cspHelper;
    }

    @Override
    public void setParent(PassiveScanThread parent) {
        // Not needed.
    }

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        // Do nothing
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        cspHelper.parse(msg);
    }

    @Override
    public String getName() {
        return "CSP Helper";
    }

    @Override
    public boolean appliesToHistoryType(int historyType) {
        return PluginPassiveScanner.getDefaultHistoryTypes().contains(historyType);
    }

    public AlertThreshold getAlertThreashold() {
        // Fixed
        return AlertThreshold.MEDIUM;
    }

    @Override
    public boolean isEnabled() {
        // Always enabled
        return true;
    }

    @Override
    public void setEnabled(boolean arg0) {
        // Ignored
    }
}
