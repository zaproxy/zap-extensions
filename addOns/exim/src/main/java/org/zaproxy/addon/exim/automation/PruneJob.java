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
package org.zaproxy.addon.exim.automation;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.automation.AutomationData;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.jobs.JobData;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.addon.exim.sites.PruneSiteResult;
import org.zaproxy.addon.exim.sites.SitesTreeHandler;

public class PruneJob extends AutomationJob {

    private static final String JOB_NAME = "prune";
    private static final String RESOURCES_DIR = "/org/zaproxy/addon/exim/resources/";

    private static final String PARAM_FILE_NAME = "fileName";

    private Parameters parameters = new Parameters();
    private Data data;

    public PruneJob() {
        this.data = new Data(this, parameters);
    }

    @Override
    public void verifyParameters(AutomationProgress progress) {
        Map<?, ?> jobData = this.getJobData();
        if (jobData == null) {
            return;
        }
        JobUtils.applyParamsToObject(
                (LinkedHashMap<?, ?>) jobData.get("parameters"),
                this.parameters,
                this.getName(),
                null,
                progress);
    }

    @Override
    public void applyParameters(AutomationProgress progress) {
        // Nothing to do
    }

    @Override
    public Map<String, String> getCustomConfigParameters() {
        Map<String, String> map = super.getCustomConfigParameters();
        map.put(PARAM_FILE_NAME, "");
        return map;
    }

    @Override
    public void runJob(AutomationEnvironment env, AutomationProgress progress) {

        String fileName = this.getParameters().getFileName();

        if (!StringUtils.isEmpty(fileName)) {
            File file = JobUtils.getFile(fileName, getPlan());
            if (!file.exists() || file.canWrite()) {
                PruneSiteResult res = SitesTreeHandler.pruneSiteNodes(file);
                if (res.getError() == null) {
                    progress.info(
                            Constant.messages.getString(
                                    "exim.automation.prune.ok.result",
                                    this.getName(),
                                    Integer.valueOf(res.getReadNodes()),
                                    file.getAbsolutePath(),
                                    Integer.valueOf(res.getDeletedNodes())));
                } else {
                    progress.error(
                            Constant.messages.getString(
                                    "exim.automation.prune.fail.result",
                                    this.getName(),
                                    Integer.valueOf(res.getReadNodes()),
                                    file.getAbsolutePath(),
                                    Integer.valueOf(res.getDeletedNodes()),
                                    res.getError()));
                }
            } else {
                progress.error(
                        Constant.messages.getString(
                                "exim.automation.import.error.file", this.getName(), fileName));
            }
        }
    }

    @Override
    public String getTemplateDataMin() {
        return getResourceAsString(this.getType() + "-min.yaml");
    }

    @Override
    public String getTemplateDataMax() {
        return getResourceAsString(this.getType() + "-max.yaml");
    }

    private static String getResourceAsString(String name) {
        try {
            return IOUtils.toString(
                    PruneJob.class.getResourceAsStream(RESOURCES_DIR + name),
                    StandardCharsets.UTF_8);
        } catch (IOException e) {
            CommandLine.error(
                    Constant.messages.getString(
                            "exim.automation.import.error.nofile", RESOURCES_DIR + name));
        }
        return "";
    }

    @Override
    public Order getOrder() {
        return Order.AFTER_EXPLORE;
    }

    @Override
    public String getType() {
        return JOB_NAME;
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
    public Parameters getParameters() {
        return parameters;
    }

    @Override
    public void showDialog() {
        new PruneJobDialog(this).setVisible(true);
    }

    @Override
    public String getSummary() {
        return Constant.messages.getString(
                "exim.automation.prune.dialog.summary",
                JobUtils.unBox(this.getParameters().getFileName(), "''"));
    }

    @Override
    public Data getData() {
        return data;
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

        public void setParameters(Parameters parameters) {
            this.parameters = parameters;
        }
    }

    public static class Parameters extends AutomationData {
        private String fileName;

        public String getFileName() {
            return fileName;
        }

        public void setFileName(String fileName) {
            this.fileName = fileName;
        }
    }
}
