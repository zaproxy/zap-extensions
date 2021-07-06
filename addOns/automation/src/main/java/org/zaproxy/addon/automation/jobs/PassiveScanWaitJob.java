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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.JobResultData;
import org.zaproxy.zap.extension.pscan.ExtensionPassiveScan;

public class PassiveScanWaitJob extends AutomationJob {

    public static final String JOB_NAME = "passiveScan-wait";

    private static final String PARAM_MAX_DURATION = "maxDuration";

    private int maxDuration = 0;

    public PassiveScanWaitJob() {}

    @Override
    public void runJob(AutomationEnvironment env, AutomationProgress progress) {
        ExtensionPassiveScan extPScan = getExtPassiveScan();

        long endTime = Long.MAX_VALUE;
        if (maxDuration > 0) {
            endTime = System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(maxDuration);
        }

        while (extPScan.getRecordsToScan() > 0) {
            if (System.currentTimeMillis() > endTime) {
                break;
            }
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                // Ignore
            }
        }
        progress.addJobResultData(this.getJobResultData());
    }

    @Override
    public List<JobResultData> getJobResultData() {
        List<JobResultData> list = new ArrayList<>();
        list.add(
                new PassiveScanJobResultData(
                        this.getName(), getExtPassiveScan().getPluginPassiveScanners()));
        return list;
    }

    private ExtensionPassiveScan getExtPassiveScan() {
        return Control.getSingleton().getExtensionLoader().getExtension(ExtensionPassiveScan.class);
    }

    private boolean verifyOrApplyCustomParameter(
            String name, String value, AutomationProgress progress) {
        switch (name) {
            case PARAM_MAX_DURATION:
                if (progress != null) {
                    try {
                        Integer.parseInt(value);
                    } catch (NumberFormatException e) {
                        progress.error(
                                Constant.messages.getString(
                                        "automation.error.options.badint",
                                        this.getType(),
                                        name,
                                        value));
                    }
                } else {
                    maxDuration = Integer.parseInt(value);
                }
                return true;
            default:
                // Ignore
                break;
        }
        return false;
    }

    @Override
    public boolean applyCustomParameter(String name, String value) {
        return this.verifyOrApplyCustomParameter(name, value, null);
    }

    @Override
    public boolean verifyCustomParameter(String name, String value, AutomationProgress progress) {
        return this.verifyOrApplyCustomParameter(name, value, progress);
    }

    public int getMaxDuration() {
        return maxDuration;
    }

    @Override
    public Map<String, String> getCustomConfigParameters() {
        Map<String, String> map = super.getCustomConfigParameters();
        map.put(PARAM_MAX_DURATION, "0");
        return map;
    }

    @Override
    public String getType() {
        return JOB_NAME;
    }

    @Override
    public Order getOrder() {
        return Order.AFTER_EXPLORE;
    }

    @Override
    public Object getParamMethodObject() {
        return null;
    }

    @Override
    public String getParamMethodName() {
        return null;
    }
}
