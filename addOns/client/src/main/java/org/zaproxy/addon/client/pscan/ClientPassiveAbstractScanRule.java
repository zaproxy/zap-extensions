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

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Alert.Source;
import org.zaproxy.addon.client.internal.ReportedObject;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;

public abstract class ClientPassiveAbstractScanRule implements ClientPassiveScanRule {

    private final Map<String, String> alertTags;
    private boolean enabled = true;

    /** Constructs a scan rule without alert tags. */
    protected ClientPassiveAbstractScanRule() {
        this(List.of());
    }

    /**
     * Constructs a scan rule with the given alert tags.
     *
     * @param policyTags the policy tags.
     * @param commonTags the common alert tags.
     */
    protected ClientPassiveAbstractScanRule(
            List<PolicyTag> policyTags, CommonAlertTag... commonTags) {
        Map<String, String> tags = CommonAlertTag.mergeTags(Map.of(), commonTags);
        policyTags.forEach(policyTag -> tags.put(policyTag.getTag(), ""));
        alertTags = Collections.unmodifiableMap(tags);
    }

    protected Alert.Builder getBaseAlertBuilder(ReportedObject obj) {
        return Alert.builder()
                .setSource(Source.PASSIVE)
                .setPluginId(getId())
                .setUri(obj.getUrl())
                .setParam(obj.getId())
                .setTags(new HashMap<>(alertTags));
    }

    @Override
    public Map<String, String> getAlertTags() {
        return alertTags;
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
