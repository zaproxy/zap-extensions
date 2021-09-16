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
package org.zaproxy.addon.retest;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import net.sf.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.RecordAlert;
import org.parosproxy.paros.db.TableAlert;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationPlan;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.addon.automation.jobs.ActiveScanJob;
import org.zaproxy.addon.automation.jobs.PassiveScanWaitJob;
import org.zaproxy.addon.automation.tests.AbstractAutomationTest;
import org.zaproxy.addon.automation.tests.AutomationAlertTest;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseList;
import org.zaproxy.zap.extension.api.ApiResponseSet;

public class RetestAPI extends ApiImplementor {
    private static final String PREFIX = "retest";

    public static final String ACTION_RETEST = "retest";
    public static final String ALERT_IDS = "alertIds";
    private ExtensionRetest extension = null;

    private static final Logger LOGGER = LogManager.getLogger(RetestAPI.class);

    public RetestAPI() {
        this(null);
    }

    public RetestAPI(ExtensionRetest extension) {
        this.extension = extension;
        this.addApiAction(new ApiAction(ACTION_RETEST, new String[] {ALERT_IDS}));
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        switch (name) {
            case ACTION_RETEST:
                List<AlertData> alerts = new ArrayList<>();
                AutomationPlan retestPlan =
                        generateRetestPlan(getParam(params, ALERT_IDS, "-1").split(","), alerts);
                ExtensionAutomation extAutomation =
                        Control.getSingleton()
                                .getExtensionLoader()
                                .getExtension(ExtensionAutomation.class);
                extAutomation.registerPlan(retestPlan);
                extAutomation.runPlan(retestPlan, true);
                return planToSet(retestPlan, alerts);
            default:
                throw new ApiException(ApiException.Type.BAD_ACTION);
        }
    }

    private AutomationPlan generateRetestPlan(String[] ids, List<AlertData> alerts)
            throws ApiException {
        ArrayList<Integer> alertIds = new ArrayList<>();
        for (String id : ids) {
            try {
                alertIds.add(Integer.valueOf(id));
            } catch (NumberFormatException e) {
                LOGGER.warn("Failed to parse alert id: {}", id);
            }
        }
        TableAlert tableAlert = Model.getSingleton().getDb().getTableAlert();
        RecordAlert recordAlert;
        for (Integer alertId : alertIds) {
            try {
                recordAlert = tableAlert.read(alertId);
            } catch (DatabaseException e) {
                LOGGER.error("Failed to read the alert from the session: {}", e.getMessage());
                throw new ApiException(ApiException.Type.INTERNAL_ERROR);
            }
            if (recordAlert == null) {
                throw new ApiException(ApiException.Type.DOES_NOT_EXIST);
            }
            alerts.add(new AlertData(new Alert(recordAlert), AlertData.Status.NOT_VERIFIED));
        }
        return extension.getPlanForAlerts(alerts);
    }

    private ApiResponseList planToSet(AutomationPlan plan, List<AlertData> alerts) {
        ApiResponseList resultList = new ApiResponseList(ACTION_RETEST);
        for (AutomationJob job : plan.getJobs()) {
            if (job.getType().equals(ActiveScanJob.JOB_NAME)
                    || job.getType().equals(PassiveScanWaitJob.JOB_NAME)) {
                for (AbstractAutomationTest test : job.getTests()) {
                    for (AlertData data : alerts) {
                        if (ExtensionRetest.testsForAlert((AutomationAlertTest) test, data)) {
                            String status = test.hasPassed() ? "Absent" : "Present";
                            resultList.addItem((alertToSet(data, status)));
                        }
                    }
                }
            }
        }
        return resultList;
    }

    private static ApiResponseSet<String> alertToSet(AlertData data, String status) {
        Map<String, String> map = new HashMap<>();
        map.put("alertId", String.valueOf(data.getAlert().getAlertId()));
        map.put("pluginId", String.valueOf(data.getScanRuleId()));
        map.put("name", data.getAlertName());
        map.put("url", data.getUrl());
        map.put("method", data.getMethod());
        map.put("status", status);

        return new ApiResponseSet<>("alert", map);
    }
}
