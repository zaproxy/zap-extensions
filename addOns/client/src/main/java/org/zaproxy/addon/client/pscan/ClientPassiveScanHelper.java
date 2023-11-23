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
package org.zaproxy.addon.client.pscan;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.zaproxy.addon.client.ClientUtils;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.utils.Stats;

public class ClientPassiveScanHelper {

    private static final Logger LOGGER = LogManager.getLogger(ClientPassiveScanHelper.class);
    private static final int MAX_HREFS_TO_CHECK = 1000;

    private ExtensionAlert extAlert;
    private ExtensionHistory extHistory;

    public ClientPassiveScanHelper(ExtensionAlert extAlert, ExtensionHistory extHistory) {
        this.extAlert = extAlert;
        this.extHistory = extHistory;
    }

    public HistoryReference findHistoryRef(String url) {
        url = ClientUtils.stripUrlFragment(url);
        int lastId = extHistory.getLastHistoryId();

        // We don't expect to have to go too far back..
        int limit = Math.max(lastId - MAX_HREFS_TO_CHECK, 0);
        LOGGER.debug("Searching for history reference for {}", url);
        for (int i = lastId; i >= limit; i--) {
            HistoryReference hr = extHistory.getHistoryReference(i);
            if (url.equals(hr.getURI().toString())) {
                LOGGER.debug("Found history reference {} for {}", hr.getHistoryId(), url);
                Stats.incCounter("stats.client.pscan.href.found");
                return hr;
            }
        }
        // Include the limit in case we change it in the future
        Stats.incCounter("stats.client.pscan.href.missing." + MAX_HREFS_TO_CHECK);
        return null;
    }

    public void raiseAlert(Alert alert, HistoryReference hr) {
        if (hr == null) {
            LOGGER.warn(
                    "Failed to find history reference for URL {}, unable to raise alert",
                    alert.getUri(),
                    alert.toPluginXML(ClientUtils.stripUrlFragment(alert.getUri())));
        } else {
            alert.setHistoryRef(hr);
            this.extAlert.alertFound(alert, hr);
        }
    }
}
