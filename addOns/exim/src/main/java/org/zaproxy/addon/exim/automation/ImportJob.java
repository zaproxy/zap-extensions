/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.automation.AutomationData;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationJobException;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.jobs.JobData;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.addon.exim.ExtensionExim;
import org.zaproxy.addon.exim.Importer;
import org.zaproxy.addon.exim.ImporterOptions;
import org.zaproxy.addon.exim.ImporterResult;
import org.zaproxy.addon.exim.ImporterType;
import org.zaproxy.addon.exim.log.LogsImporter;
import org.zaproxy.addon.exim.urls.UrlExporter;
import org.zaproxy.addon.exim.urls.UrlsImporter;
import org.zaproxy.zap.utils.Stats;
import org.zaproxy.zap.utils.ThreadUtils;

public class ImportJob extends AutomationJob {

    private static final String JOB_NAME = "import";
    private static final String RESOURCES_DIR = "/org/zaproxy/addon/exim/resources/";

    private static final String PARAM_TYPE = "type";
    private static final String PARAM_FILE_NAME = "fileName";

    /** Import type ID for ModSecurity2 logs. */
    static final String MODSEC2_TYPE = "modsec2";

    /** Import type ID for ZAP messages import. */
    static final String ZAP_MESSAGES_TYPE = "zap_messages";

    private final ExtensionExim extensionExim;
    private Parameters parameters = new Parameters();
    private Data data;

    public ImportJob(ExtensionExim extensionExim) {
        this.extensionExim = extensionExim;
        this.data = new Data(this, parameters);
    }

    @Override
    public AutomationJob newJob() throws AutomationJobException {
        return new ImportJob(extensionExim);
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
        map.put(PARAM_TYPE, "");
        map.put(PARAM_FILE_NAME, "");
        return map;
    }

    @Override
    public void runJob(AutomationEnvironment env, AutomationProgress progress) {

        String type = this.getParameters().getType();
        String fileName = this.getParameters().getFileName();

        if (!StringUtils.isEmpty(fileName)) {
            File file = JobUtils.getFile(fileName, getPlan());
            if (file.exists() && file.canRead()) {
                ImporterType importerType = Importer.getImporterType(type);
                if (importerType != null) {
                    ImporterResult result =
                            extensionExim
                                    .getImporter()
                                    .apply(
                                            ImporterOptions.builder()
                                                    .setType(type)
                                                    .setInputFile(file.toPath())
                                                    .setMessageHandler(
                                                            msg -> persistMessage(progress, msg))
                                                    .build());
                    if (!result.getErrors().isEmpty()) {
                        for (String error : result.getErrors()) {
                            progress.error(error);
                        }
                    }
                } else if (MODSEC2_TYPE.equalsIgnoreCase(type)) {
                    LogsImporter logsImporter =
                            new LogsImporter(file, LogsImporter.LogType.MOD_SECURITY_2);
                    if (!logsImporter.isSuccess()) {
                        progress.error(
                                Constant.messages.getString(
                                        "exim.automation.import.error",
                                        file.getAbsolutePath(),
                                        Constant.messages.getString(
                                                "exim.options.value.type.modsec2")));
                    }
                } else if (UrlExporter.ID.equalsIgnoreCase(type)) {
                    UrlsImporter urlsImporter = new UrlsImporter(file);
                    if (!urlsImporter.isSuccess()) {
                        progress.error(
                                Constant.messages.getString(
                                        "exim.automation.import.error",
                                        file.getAbsolutePath(),
                                        Constant.messages.getString(
                                                "exim.options.value.type.url")));
                    }
                } else if (ZAP_MESSAGES_TYPE.equalsIgnoreCase(type)) {
                    LogsImporter zapImporter = new LogsImporter(file, LogsImporter.LogType.ZAP);
                    if (!zapImporter.isSuccess()) {
                        progress.error(
                                Constant.messages.getString(
                                        "exim.automation.import.error",
                                        file.getAbsolutePath(),
                                        Constant.messages.getString(
                                                "exim.options.value.type.zapmessages")));
                    }
                } else {
                    progress.error(
                            Constant.messages.getString(
                                    "exim.automation.import.error.type", this.getName(), type));
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

    private void persistMessage(AutomationProgress progress, HttpMessage message) {
        try {
            HistoryReference historyRef =
                    new HistoryReference(
                            extensionExim.getModel().getSession(),
                            HistoryReference.TYPE_ZAP_USER,
                            message);
            Stats.incCounter(ExtensionExim.STATS_PREFIX + "import.automation.message");
            ExtensionHistory extHistory =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionHistory.class);
            if (extHistory != null) {
                ThreadUtils.invokeAndWaitHandled(
                        () -> {
                            extHistory.addHistory(historyRef);
                            extensionExim
                                    .getModel()
                                    .getSession()
                                    .getSiteTree()
                                    .addPath(historyRef, message);
                        });
            }
        } catch (Exception e) {
            progress.warn(
                    Constant.messages.getString(
                            "exim.automation.import.error.message", e.getLocalizedMessage()));
        }
    }

    private static String getResourceAsString(String name) {
        try {
            return IOUtils.toString(
                    ImportJob.class.getResourceAsStream(RESOURCES_DIR + name),
                    StandardCharsets.UTF_8);
        } catch (IOException e) {
            CommandLine.error(
                    Constant.messages.getString(
                            "exim.automation.error.noresourcefile", RESOURCES_DIR + name));
        }
        return "";
    }

    @Override
    public Order getOrder() {
        return Order.EXPLORE;
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
        new ImportJobDialog(this).setVisible(true);
    }

    @Override
    public String getSummary() {
        return Constant.messages.getString(
                "exim.automation.import.dialog.summary",
                JobUtils.unBox(this.getParameters().getType(), "''"),
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

    @Getter
    @Setter
    public static class Parameters extends AutomationData {
        private String type;
        private String fileName;
    }
}
