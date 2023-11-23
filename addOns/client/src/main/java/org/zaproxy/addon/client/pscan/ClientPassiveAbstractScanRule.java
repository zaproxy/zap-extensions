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

import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Alert.Source;
import org.zaproxy.addon.client.ReportedObject;

public abstract class ClientPassiveAbstractScanRule implements ClientPassiveScanRule {

    private boolean enabled = true;

    protected Alert.Builder getBaseAlertBuilder(ReportedObject obj) {
        return Alert.builder()
                .setSource(Source.PASSIVE)
                .setPluginId(getId())
                .setUri(obj.getUrl())
                .setParam(obj.getId());
    }

    @Override
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    public boolean isEnabled() {
        return this.enabled;
    }

    @Override
    public String getHelpLink() {
        return "https://www.zaproxy.org/docs/desktop/addons/client-side-integration/pscan/#id-"
                + getId();
    }
}
