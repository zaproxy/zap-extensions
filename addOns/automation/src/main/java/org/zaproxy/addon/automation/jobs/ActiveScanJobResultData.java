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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.HostProcess;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.RecordAlert;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.automation.JobResultData;
import org.zaproxy.zap.extension.ascan.ActiveScan;

public class ActiveScanJobResultData extends JobResultData {

    private static final Logger LOG = LogManager.getLogger(ActiveScanJobResultData.class);
    public static final String KEY = "activeScanData";

    private Map<Integer, RuleData> ruleDataMap = new HashMap<>();
    private Map<Integer, Alert> alertDataMap = new HashMap<>();

    public ActiveScanJobResultData(String jobName, ActiveScan activeScan) {
        super(jobName);

        RuleData data;
        for (HostProcess hp : activeScan.getHostProcesses()) {
            for (Plugin plugin : hp.getCompleted()) {
                data =
                        ruleDataMap.computeIfAbsent(
                                plugin.getId(),
                                k -> new RuleData(plugin.getId(), plugin.getName()));
                data.incTimeTakenMs(
                        plugin.getTimeStarted().getTime() - plugin.getTimeFinished().getTime());
                data.setStrength(plugin.getAttackStrength());
                data.setThreshold(plugin.getAlertThreshold());
            }
        }
        List<Integer> alertIds = activeScan.getAlertsIds();
        for (int id : alertIds) {
            try {
                RecordAlert recordAlert = Model.getSingleton().getDb().getTableAlert().read(id);
                if (recordAlert != null) {
                    alertDataMap.put(id, new Alert(recordAlert));
                }
            } catch (DatabaseException e) {
                LOG.error("Could not read alert with id {} from the database : {}", id, e);
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
    public Alert getAlertData(int alertId) {
        return alertDataMap.get(alertId);
    }

    @Override
    public Collection<Alert> getAllAlertData() {
        return alertDataMap.values();
    }

    @Override
    public String getKey() {
        return KEY;
    }

    public static class RuleData {
        private final int id;
        private final String name;
        private long timeTakenMs;
        private Plugin.AlertThreshold threshold;
        private Plugin.AttackStrength strength;

        public RuleData(int id, String name) {
            this.id = id;
            this.name = name;
        }

        public void incTimeTakenMs(long time) {
            this.timeTakenMs += time;
        }

        public Plugin.AlertThreshold getThreshold() {
            return threshold;
        }

        public void setThreshold(Plugin.AlertThreshold threshold) {
            this.threshold = threshold;
        }

        public Plugin.AttackStrength getStrength() {
            return strength;
        }

        public void setStrength(Plugin.AttackStrength strength) {
            this.strength = strength;
        }

        public int getId() {
            return id;
        }

        public String getName() {
            return name;
        }

        public long getTimeTakenMs() {
            return timeTakenMs;
        }
    }
}
