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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Collectors;

public class ClientPassiveScanController {

    private List<ClientPassiveScanRule> scanRules;

    private boolean enabled = true;

    public ClientPassiveScanController() {
        scanRules = new ArrayList<>();
        scanRules.add(new InformationInStorageScanRule());
        scanRules.add(new SensitiveInfoInStorageScanRule());
        scanRules.add(new JwtInStorageScanRule());
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public List<ClientPassiveScanRule> getAllScanRules() {
        return Collections.unmodifiableList(scanRules);
    }

    public List<ClientPassiveScanRule> getEnabledScanRules() {
        if (!enabled) {
            return Collections.emptyList();
        }
        return scanRules.stream()
                .filter(ClientPassiveScanRule::isEnabled)
                .collect(Collectors.toList());
    }

    public List<ClientPassiveScanRule> getDisabledScanRules() {
        return scanRules.stream()
                .filter(Predicate.not(ClientPassiveScanRule::isEnabled))
                .collect(Collectors.toList());
    }

    /**
     * Enables all of the scan rules included in the list and disables the rest.
     *
     * @param enabledScanRules the scan rules to be enabled
     */
    public void setEnabledScanRules(List<ClientPassiveScanRule> enabledScanRules) {
        scanRules.forEach(s -> s.setEnabled(false));
        enabledScanRules.forEach(s -> s.setEnabled(enabledScanRules.contains(s)));
    }

    /**
     * Disables all of the scan rules with IDs included in the list and enables the rest.
     *
     * @param disabledScanRuleIds the scan rule IDs to be disabled
     */
    public void setDisabledScanRules(List<Integer> disabledScanRuleIds) {
        scanRules.forEach(s -> s.setEnabled(!disabledScanRuleIds.contains(s.getId())));
    }
}
