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

import java.io.File;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.automation.AutomationData;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.HhMmSs;
import org.zaproxy.addon.automation.gui.DelayJobDialog;

public class DelayJob extends AutomationJob {

    public static final String JOB_NAME = "delay";

    private Data data;
    private Parameters parameters = new Parameters();
    private static boolean endJob;

    public DelayJob() {
        this.data = new Data(this, parameters);
    }

    @Override
    public void verifyParameters(AutomationProgress progress) {
        Map<?, ?> jobData = this.getJobData();
        if (jobData != null) {
            JobUtils.applyParamsToObject(
                    (LinkedHashMap<?, ?>) jobData.get("parameters"),
                    this.parameters,
                    this.getName(),
                    null,
                    progress);
        }

        String timeStr = this.getParameters().getTime();
        try {
            new HhMmSs(timeStr);
        } catch (Exception e) {
            progress.error(Constant.messages.getString("automation.error.delay.badtime", timeStr));
        }
    }

    @Override
    public void applyParameters(AutomationProgress progress) {}

    @Override
    public void runJob(AutomationEnvironment env, AutomationProgress progress) {
        setEndJob(false);
        HhMmSs hhmmss;
        File file = null;
        try {
            hhmmss = new HhMmSs(this.getParameters().getTime());
        } catch (Exception e) {
            // Will have warned the user during the verify
            return;
        }
        if (!StringUtils.isEmpty(this.getParameters().getFileName())) {
            file = new File(this.getParameters().getFileName());
        }
        long end = System.currentTimeMillis() + hhmmss.getTimeInMs();
        try {
            while (System.currentTimeMillis() < end
                    && !endJob
                    && !(file != null && file.exists())) {
                Thread.sleep(TimeUnit.SECONDS.toMillis(1));
            }
            if (endJob) {
                progress.info(
                        Constant.messages.getString(
                                "automation.info.delay.endjob", this.getName()));
            } else if (file != null && file.exists()) {
                progress.info(
                        Constant.messages.getString(
                                "automation.info.delay.filecreated",
                                this.getName(),
                                file.getAbsolutePath()));
            } else {
                progress.info(
                        Constant.messages.getString(
                                "automation.info.delay.timeout",
                                this.getName(),
                                this.getParameters().getTime()));
            }
        } catch (InterruptedException e) {
            // Looks like something really does want us to stop
            Thread.currentThread().interrupt();
            progress.info(
                    Constant.messages.getString(
                            "automation.info.delay.interrupted", this.getName()));
        }
    }

    public static void setEndJob(boolean bool) {
        endJob = bool;
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

    @Override
    public void showDialog() {
        new DelayJobDialog(this).setVisible(true);
    }

    @Override
    public String getSummary() {
        return Constant.messages.getString(
                "automation.dialog.delay.summary",
                this.getData().getParameters().getTime(),
                this.getData().getParameters().getFileName());
    }

    @Override
    public Data getData() {
        return data;
    }

    @Override
    public Parameters getParameters() {
        return this.parameters;
    }

    public static class Data extends JobData {
        private Parameters parameters;

        public Data(AutomationJob job, Parameters parameters) {
            super(job);
            this.parameters = parameters;
        }

        public Parameters getParameters() {
            return parameters;
        }
    }

    public static class Parameters extends AutomationData {
        private String time;
        private String fileName;

        public String getTime() {
            return time;
        }

        public void setTime(String time) {
            this.time = time;
        }

        public String getFileName() {
            return fileName;
        }

        public void setFileName(String fileName) {
            this.fileName = fileName;
        }
    }
}
