/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.automation.jobs;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Plugin;
import org.zaproxy.addon.automation.JobResultData;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.extension.stats.ExtensionStats;
import org.zaproxy.zap.extension.stats.InMemoryStats;

public class PassiveScanJobResultData extends JobResultData {

    private Map<Integer, RuleData> ruleDataMap = new HashMap<>();

    public PassiveScanJobResultData(String jobName, List<PluginPassiveScanner> list) {
        super(jobName);

        ExtensionStats extStats =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionStats.class);

        InMemoryStats stats = null;
        if (extStats != null) {
            stats = extStats.getInMemoryStats();
        }

        RuleData data;
        for (PluginPassiveScanner scanner : list) {
            data = new RuleData(scanner);
            ruleDataMap.put(data.getId(), data);
            if (stats != null) {
                data.setTimeTakenMs(stats.getStat("stats.pscan." + data.name));
            }
        }
    }

    public RuleData getRuleData(int ruleId) {
        return ruleDataMap.get(ruleId);
    }

    public Collection<RuleData> getAllRuleData() {
        return ruleDataMap.values();
    }

    @Override
    public String getKey() {
        return "passiveScanData";
    }

    public static class RuleData {
        private final int id;
        private final String name;
        private long timeTakenMs;
        private final Plugin.AlertThreshold threshold;

        public RuleData(PluginPassiveScanner scanner) {
            this.id = scanner.getPluginId();
            this.name = scanner.getName();
            this.threshold = scanner.getAlertThreshold();
        }

        public Plugin.AlertThreshold getThreshold() {
            return threshold;
        }

        public int getId() {
            return id;
        }

        public String getName() {
            return name;
        }

        public void setTimeTakenMs(Long timeTakenMs) {
            if (timeTakenMs != null) {
                this.timeTakenMs = timeTakenMs;
            }
        }

        public long getTimeTakenMs() {
            return timeTakenMs;
        }
    }
}
