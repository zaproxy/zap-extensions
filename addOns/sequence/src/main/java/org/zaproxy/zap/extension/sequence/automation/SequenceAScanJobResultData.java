/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.zap.extension.sequence.automation;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import lombok.Getter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.RecordAlert;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.automation.JobResultData;
import org.zaproxy.zap.extension.sequence.StdActiveScanRunner.SequenceStepData;

@Getter
public class SequenceAScanJobResultData extends JobResultData {

    private static final Logger LOGGER = LogManager.getLogger(SequenceAScanJobResultData.class);

    public static final String KEY = "seqAScanData";

    private List<SequenceData> seqData = new ArrayList<>();
    private Map<Integer, Alert> alertDataMap;

    public SequenceAScanJobResultData(String jobName) {
        super(jobName);
    }

    public void addSequenceData(String sequenceName, List<SequenceStepData> steps) {
        seqData.add(new SequenceData(sequenceName, steps));
    }

    @Override
    public String getKey() {
        return KEY;
    }

    @Override
    public Alert getAlertData(int alertId) {
        return getAlertDataMap().get(alertId);
    }

    @Override
    public Collection<Alert> getAllAlertData() {
        return getAlertDataMap().values();
    }

    private Map<Integer, Alert> getAlertDataMap() {
        if (alertDataMap == null) {
            Map<Integer, Alert> data = new HashMap<Integer, Alert>();
            seqData.forEach(
                    sequenceData ->
                            sequenceData.getSteps().forEach(step -> addStepAlerts(data, step)));

            alertDataMap = Collections.unmodifiableMap(data);
        }
        return alertDataMap;
    }

    private static void addStepAlerts(Map<Integer, Alert> data, SequenceStepData step) {
        List<Integer> alertIds = step.getAlertIds();
        for (int id : alertIds) {
            try {
                RecordAlert recordAlert = Model.getSingleton().getDb().getTableAlert().read(id);
                if (recordAlert != null) {
                    data.put(id, new Alert(recordAlert));
                }
            } catch (DatabaseException e) {
                LOGGER.error("Could not read alert with ID {} from the database:", id, e);
            }
        }
    }

    @Getter
    public static class SequenceData {
        private String sequenceName;
        private List<SequenceStepData> steps;

        public SequenceData(String sequenceName, List<SequenceStepData> steps) {
            this.sequenceName = sequenceName;
            this.steps = steps;
        }
    }
}
