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
package org.zaproxy.addon.llm.automation;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import lombok.Getter;
import lombok.Setter;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.addon.automation.AutomationData;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.jobs.JobData;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.addon.llm.ExtensionLlm;
import org.zaproxy.addon.llm.LlmProvider;

/** Automation job that configures the LLM providers. */
public class LlmConfigJob extends AutomationJob {

    public static final String JOB_NAME = "llm-config";

    private static final String PROVIDERS_KEY = "providers";
    private static final String RESOURCES_DIR = "/org/zaproxy/addon/llm/resources/";

    private final ExtensionLlm extLlm;
    private final Parameters parameters = new Parameters();
    private final Data data;

    public LlmConfigJob() {
        this(Control.getSingleton().getExtensionLoader().getExtension(ExtensionLlm.class));
    }

    /** Constructor for testing, avoids looking the extension up from Control. */
    LlmConfigJob(ExtensionLlm extLlm) {
        this.extLlm = extLlm;
        this.data = new Data(this, parameters);
    }

    @Override
    public void verifyParameters(AutomationProgress progress) {
        Map<?, ?> jobData = getJobData();
        if (jobData == null) {
            return;
        }
        JobUtils.applyParamsToObject(
                (Map<?, ?>) jobData.get("parameters"), parameters, getName(), null, progress);

        List<Provider> providers = new ArrayList<>();
        Object providersData = jobData.get(PROVIDERS_KEY);
        if (providersData instanceof List<?> list) {
            for (Object item : list) {
                if (item instanceof Map<?, ?> map) {
                    Provider provider = new Provider();
                    JobUtils.applyParamsToObject(map, provider, getName(), null, progress);
                    providers.add(provider);
                } else {
                    progress.error(
                            Constant.messages.getString(
                                    "llm.configjob.error.badprovider", getName(), item));
                }
            }
        } else if (providersData != null) {
            progress.error(
                    Constant.messages.getString(
                            "llm.configjob.error.badlist", getName(), providersData));
        }
        data.setProviders(providers);

        LlmProviderConfigMerger.merge(extLlm.getOptions(), parameters, providers)
                .errors()
                .forEach(progress::error);
    }

    /**
     * Validates a provider, as it would be applied to the current options.
     *
     * @return the first problem found, or {@code null} if there are none
     */
    String validateProvider(Provider provider, boolean deleteExisting) {
        return LlmProviderConfigMerger.validate(extLlm.getOptions(), provider, deleteExisting)
                .stream()
                .findFirst()
                .orElse(null);
    }

    @Override
    public void applyParameters(AutomationProgress progress) {
        // Applied in runJob, the providers are not simple options.
    }

    @Override
    public void runJob(AutomationEnvironment env, AutomationProgress progress) {
        LlmProviderConfigMerger.Result result =
                LlmProviderConfigMerger.merge(extLlm.getOptions(), parameters, data.getProviders());
        if (!result.errors().isEmpty()) {
            result.errors().forEach(progress::error);
            return;
        }
        extLlm.updateProviders(result.providers(), result.defaultProvider(), result.defaultModel());
        progress.info(
                Constant.messages.getString("llm.configjob.info.done", result.providers().size()));
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
    public String getSummary() {
        return Constant.messages.getString("llm.configjob.summary", data.getProviders().size());
    }

    @Override
    public void showDialog() {
        new LlmConfigJobDialog(this).setVisible(true);
    }

    @Override
    public String getTemplateDataMin() {
        return getResourceAsString(RESOURCES_DIR + "llm-config-min.yaml");
    }

    @Override
    public String getTemplateDataMax() {
        return getResourceAsString(RESOURCES_DIR + "llm-config-max.yaml");
    }

    private static String getResourceAsString(String name) {
        try (InputStream in = LlmConfigJob.class.getResourceAsStream(name)) {
            return in == null ? null : new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            return null;
        }
    }

    @Getter
    @Setter
    public static class Parameters extends AutomationData {
        private Boolean deleteExisting;
        private String defaultProvider;
        private String defaultModel;
    }

    @Getter
    @Setter
    public static class Provider extends AutomationData {
        private String name;
        private LlmProvider type;
        private String apiKey;
        private String endpoint;
        private List<String> models;
        private Boolean trusted;
        private Integer timeout;
    }

    @Getter
    public static class Data extends JobData {
        private final Parameters parameters;
        @Setter private List<Provider> providers = new ArrayList<>();

        public Data(AutomationJob job, Parameters parameters) {
            super(job);
            this.parameters = parameters;
        }
    }
}
