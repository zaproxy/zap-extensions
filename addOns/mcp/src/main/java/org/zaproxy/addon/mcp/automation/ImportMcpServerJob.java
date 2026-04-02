/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.mcp.automation;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.automation.AutomationData;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.jobs.JobData;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.addon.mcp.importer.McpImporter;

/**
 * Automation job that imports an external MCP server into ZAP's history and sites tree by probing
 * all accessible endpoints.
 */
public class ImportMcpServerJob extends AutomationJob {

    private static final String JOB_NAME = "mcp-import";
    private static final String RESOURCES_DIR = "/org/zaproxy/addon/mcp/resources/";

    private final McpImporter importer;
    private final Parameters parameters = new Parameters();
    private final Data data;

    public ImportMcpServerJob() {
        this(new McpImporter());
    }

    /**
     * Constructor for testing — accepts a pre-built {@link McpImporter} to avoid ZAP
     * infrastructure.
     */
    ImportMcpServerJob(McpImporter importer) {
        this.importer = importer;
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

        if (parameters.getServerUrl() == null || parameters.getServerUrl().isBlank()) {
            progress.error(
                    Constant.messages.getString("mcp.importserver.job.error.missingserverurl"));
        }
    }

    @Override
    public void applyParameters(AutomationProgress progress) {
        // Nothing to do
    }

    @Override
    public Map<String, String> getCustomConfigParameters() {
        return Map.of();
    }

    @Override
    public void runJob(AutomationEnvironment env, AutomationProgress progress) {
        McpImporter.ImportResults results =
                importer.importServer(
                        new McpImporter.ImportConfig(
                                parameters.getServerUrl(), parameters.getSecurityKey()));

        for (String error : results.errors()) {
            progress.warn(error);
        }
        progress.info(
                Constant.messages.getString(
                        "mcp.importserver.job.imported", results.requestCount()));
    }

    @Override
    public String getType() {
        return JOB_NAME;
    }

    @Override
    public Order getOrder() {
        return Order.EXPLORE;
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
    public Data getData() {
        return data;
    }

    @Override
    public Parameters getParameters() {
        return parameters;
    }

    @Override
    public void showDialog() {
        if (View.isInitialised()) {
            new ImportMcpServerJobDialog(this).setVisible(true);
        }
    }

    @Override
    public String getTemplateDataMin() {
        return getResourceAsString(RESOURCES_DIR + "mcp-import-min.yaml");
    }

    @Override
    public String getTemplateDataMax() {
        return getResourceAsString(RESOURCES_DIR + "mcp-import-max.yaml");
    }

    private static String getResourceAsString(String name) {
        try (InputStream in = ImportMcpServerJob.class.getResourceAsStream(name)) {
            if (in == null) {
                return null;
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            return null;
        }
    }

    public static class Parameters extends AutomationData {
        private String serverUrl;
        private String securityKey;

        public String getServerUrl() {
            return serverUrl;
        }

        public void setServerUrl(String serverUrl) {
            this.serverUrl = serverUrl;
        }

        public String getSecurityKey() {
            return securityKey;
        }

        public void setSecurityKey(String securityKey) {
            this.securityKey = securityKey;
        }
    }

    public static class Data extends JobData {

        private final Parameters parameters;

        public Data(AutomationJob job, Parameters parameters) {
            super(job);
            this.parameters = parameters;
        }

        public Parameters getParameters() {
            return parameters;
        }
    }
}
