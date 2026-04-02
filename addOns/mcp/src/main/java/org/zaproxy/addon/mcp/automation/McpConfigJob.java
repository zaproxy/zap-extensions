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
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.automation.AutomationData;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.jobs.JobData;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.addon.mcp.ExtensionMcp;
import org.zaproxy.addon.mcp.McpParam;

/** Automation job that configures the MCP server. */
public class McpConfigJob extends AutomationJob {

    public static final String JOB_NAME = "mcp-config";
    private static final String RESOURCES_DIR = "/org/zaproxy/addon/mcp/resources/";

    private final ExtensionMcp extMcp;
    private final Parameters parameters = new Parameters();
    private final Data data;

    public McpConfigJob() {
        this(Control.getSingleton().getExtensionLoader().getExtension(ExtensionMcp.class));
    }

    /**
     * Constructor for testing — accepts a pre-built {@link ExtensionMcp} to avoid looking it up
     * from Control.
     */
    McpConfigJob(ExtensionMcp extMcp) {
        this.extMcp = extMcp;
        this.data = new Data(this, parameters);
        // Pre-populate with current values so the dialog shows meaningful defaults
        McpParam p = extMcp.getMcpParam();
        parameters.setEnabled(p.isEnabled());
        parameters.setPort(p.getPort());
        parameters.setSecurityKeyEnabled(p.isSecurityKeyEnabled());
        parameters.setSecurityKey(p.getSecurityKey());
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

        if (parameters.getPort() != null
                && (parameters.getPort() < 1 || parameters.getPort() > 65535)) {
            progress.error(Constant.messages.getString("mcp.optionspanel.port.error.invalid"));
        }
        if (Boolean.TRUE.equals(parameters.getSecurityKeyEnabled())
                && StringUtils.isEmpty(parameters.getSecurityKey())) {
            progress.error(Constant.messages.getString("mcp.optionspanel.securitykey.error.empty"));
        }
    }

    @Override
    public void applyParameters(AutomationProgress progress) {
        // Applied in runJob to ensure server restart happens at the right time
    }

    @Override
    public Map<String, String> getCustomConfigParameters() {
        return Map.of();
    }

    @Override
    public void runJob(AutomationEnvironment env, AutomationProgress progress) {
        McpParam mcpParam = extMcp.getMcpParam();

        if (parameters.getEnabled() != null) {
            mcpParam.setEnabled(parameters.getEnabled());
        }
        if (parameters.getPort() != null) {
            mcpParam.setPort(parameters.getPort());
        }
        if (parameters.getSecurityKeyEnabled() != null) {
            mcpParam.setSecurityKeyEnabled(parameters.getSecurityKeyEnabled());
        }
        if (parameters.getSecurityKey() != null && !parameters.getSecurityKey().isBlank()) {
            mcpParam.setSecurityKey(parameters.getSecurityKey());
        }

        extMcp.applyServerConfig();
        progress.info(Constant.messages.getString("mcp.configjob.info.done"));
    }

    @Override
    public String getType() {
        return JOB_NAME;
    }

    @Override
    public Order getOrder() {
        return Order.CONFIGS;
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
            new McpConfigJobDialog(this).setVisible(true);
        }
    }

    @Override
    public String getTemplateDataMin() {
        return getResourceAsString(RESOURCES_DIR + "mcp-config-min.yaml");
    }

    @Override
    public String getTemplateDataMax() {
        return getResourceAsString(RESOURCES_DIR + "mcp-config-max.yaml");
    }

    private static String getResourceAsString(String name) {
        try (InputStream in = McpConfigJob.class.getResourceAsStream(name)) {
            if (in == null) {
                return null;
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            return null;
        }
    }

    public static class Parameters extends AutomationData {
        private Boolean enabled;
        private Integer port;
        private Boolean securityKeyEnabled;
        private String securityKey;

        public Boolean getEnabled() {
            return enabled;
        }

        public void setEnabled(Boolean enabled) {
            this.enabled = enabled;
        }

        public Integer getPort() {
            return port;
        }

        public void setPort(Integer port) {
            this.port = port;
        }

        public Boolean getSecurityKeyEnabled() {
            return securityKeyEnabled;
        }

        public void setSecurityKeyEnabled(Boolean securityKeyEnabled) {
            this.securityKeyEnabled = securityKeyEnabled;
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
