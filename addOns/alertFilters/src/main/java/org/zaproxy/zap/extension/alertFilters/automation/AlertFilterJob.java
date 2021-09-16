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
package org.zaproxy.zap.extension.alertFilters.automation;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.apache.commons.lang.StringUtils;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.addon.automation.AutomationData;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.jobs.JobData;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.zap.extension.alertFilters.AlertFilter;
import org.zaproxy.zap.extension.alertFilters.ExtensionAlertFilters;
import org.zaproxy.zap.model.Context;

public class AlertFilterJob extends AutomationJob {

    public enum Risk {
        FALSE_POSITIVE(-1, "alertFilters.panel.newalert.fp") {
            @Override
            public String toString() {
                return "False Positive";
            }
        },
        INFO(0, "alertFilters.panel.newalert.info") {
            @Override
            public String toString() {
                return "Info";
            }
        },
        LOW(1, "alertFilters.panel.newalert.low") {
            @Override
            public String toString() {
                return "Low";
            }
        },
        MEDIUM(2, "alertFilters.panel.newalert.medium") {
            @Override
            public String toString() {
                return "Medium";
            }
        },
        HIGH(3, "alertFilters.panel.newalert.high") {
            @Override
            public String toString() {
                return "High";
            }
        };

        private final int id;
        private final String i18nString;

        private Risk(int id, String i18nString) {
            this.id = id;
            this.i18nString = i18nString;
        };

        public int getId() {
            return this.id;
        }

        public String getI18nString() {
            return Constant.messages.getString(i18nString);
        }

        public static Risk getRisk(String name) {
            for (Risk risk : Risk.values()) {
                if (risk.toString().equalsIgnoreCase(name)) {
                    return risk;
                }
            }
            return null;
        }

        public static Risk getRiskFromI18n(String name) {
            for (Risk risk : Risk.values()) {
                if (risk.getI18nString().equalsIgnoreCase(name)) {
                    return risk;
                }
            }
            return null;
        }

        public static boolean isValidRisk(String name) {
            return getRisk(name) != null;
        }
    }

    private static final String JOB_NAME = "alertFilter";
    private static final String RESOURCES_DIR =
            "/org/zaproxy/zap/extension/alertFilters/resources/";

    private ExtensionAlertFilters extAlertFilters;

    private Data data;

    public AlertFilterJob() {
        data = new Data(this);
    }

    private ExtensionAlertFilters getExtAlertFilters() {
        if (extAlertFilters == null) {
            extAlertFilters =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionAlertFilters.class);
        }
        return extAlertFilters;
    }

    @Override
    public void verifyParameters(AutomationProgress progress) {
        Map<?, ?> jobData = this.getJobData();
        if (jobData == null) {
            return;
        }
        Object alertFiltersObject = jobData.get("alertFilters");
        if (alertFiltersObject == null) {
            progress.warn(
                    Constant.messages.getString(
                            "alertFilters.automation.error.nofilters", this.getName()));
            return;
        }
        if (!(alertFiltersObject instanceof ArrayList)) {
            progress.error(
                    Constant.messages.getString(
                            "alertFilters.automation.error.badfilters", this.getName()));
            return;
        }
        ArrayList<?> alertFiltersData = (ArrayList<?>) alertFiltersObject;
        for (Object alertFilterObject : alertFiltersData.toArray()) {
            if (!(alertFilterObject instanceof LinkedHashMap)) {
                progress.error(
                        Constant.messages.getString(
                                "alertFilters.automation.error.badfilter",
                                this.getName(),
                                alertFilterObject.toString()));
                return;
            }
            AlertFilterData afd = new AlertFilterData();
            JobUtils.applyParamsToObject(
                    (LinkedHashMap<?, ?>) alertFilterObject, afd, this.getName(), null, progress);
            if (this.isValid(afd, progress)) {
                this.getData().addAlertFilters(afd);
            }
        }
    }

    private boolean isValid(AlertFilterData afd, AutomationProgress progress) {
        boolean result = true;
        if (afd.getRuleId() <= 0) {
            progress.error(
                    Constant.messages.getString(
                            "alertFilters.automation.error.noruleid", this.getName()));
            result = false;
        }
        if (!Risk.isValidRisk(afd.getNewRisk())) {
            progress.error(
                    Constant.messages.getString(
                            "alertFilters.automation.error.badrisk",
                            this.getName(),
                            afd.getNewRisk()));
            result = false;
        }
        if (JobUtils.unBox(afd.getUrlRegex())) {
            try {
                Pattern.compile(afd.getUrl());
            } catch (Exception e) {
                progress.error(
                        Constant.messages.getString(
                                "alertFilters.automation.error.badurlregex",
                                this.getName(),
                                afd.getUrl()));
                result = false;
            }
        }
        if (JobUtils.unBox(afd.getParameterRegex())) {
            try {
                Pattern.compile(afd.getParameter());
            } catch (Exception e) {
                progress.error(
                        Constant.messages.getString(
                                "alertFilters.automation.error.badparamregex",
                                this.getName(),
                                afd.getParameter()));
                result = false;
            }
        }
        if (JobUtils.unBox(afd.getAttackRegex())) {
            try {
                Pattern.compile(afd.getAttack());
            } catch (Exception e) {
                progress.error(
                        Constant.messages.getString(
                                "alertFilters.automation.error.badattackregex",
                                this.getName(),
                                afd.getAttack()));
                result = false;
            }
        }
        if (JobUtils.unBox(afd.getEvidenceRegex())) {
            try {
                Pattern.compile(afd.getEvidence());
            } catch (Exception e) {
                progress.error(
                        Constant.messages.getString(
                                "alertFilters.automation.error.badevidenceregex",
                                this.getName(),
                                afd.getEvidence()));
                result = false;
            }
        }
        return result;
    }

    @Override
    public Map<String, String> getCustomConfigParameters() {
        Map<String, String> map = super.getCustomConfigParameters();
        return map;
    }

    @Override
    public void runJob(AutomationEnvironment env, AutomationProgress progress) {

        if (JobUtils.unBox(this.getData().getParameters().getDeleteGlobalAlerts())) {
            this.getExtAlertFilters().deleteAllGlobalAlertFilters();
            progress.info(
                    Constant.messages.getString(
                            "alertFilters.automation.info.globaldelete", this.getName()));
        }
        List<AlertFilterData> alertFilters = this.getData().getAlertFilters();
        if (alertFilters != null) {
            AlertFilter af;
            for (AlertFilterData afd : alertFilters) {
                String contextName = afd.getContext();
                if (StringUtils.isEmpty(contextName)) {
                    // Its a global filter
                    af = this.dataToAlertFilter(-1, afd, env, progress);
                    if (af != null) {
                        this.getExtAlertFilters().addGlobalAlertFilter(af);
                        progress.info(
                                Constant.messages.getString(
                                        "alertFilters.automation.info.globaladd",
                                        this.getName(),
                                        af.getRuleId(),
                                        af.getNewRiskName()));
                    }
                } else {
                    Context ctx = env.getContext(afd.getContext());
                    if (ctx == null) {
                        progress.error(
                                Constant.messages.getString(
                                        "automation.error.context.unknown", afd.getContext()));

                    } else {
                        af = this.dataToAlertFilter(ctx.getId(), afd, env, progress);
                        if (af != null) {
                            this.getExtAlertFilters()
                                    .getContextAlertFilterManager(ctx.getId())
                                    .addAlertFilter(af);
                            progress.info(
                                    Constant.messages.getString(
                                            "alertFilters.automation.info.contextadd",
                                            this.getName(),
                                            contextName,
                                            af.getRuleId(),
                                            af.getNewRiskName()));
                        }
                    }
                }
            }
        }
    }

    protected AlertFilter dataToAlertFilter(
            int contextId,
            AlertFilterData data,
            AutomationEnvironment env,
            AutomationProgress progress) {
        Risk newRisk = Risk.getRisk(data.getNewRisk());
        if (newRisk == null) {
            return null;
        }

        return new AlertFilter(
                contextId,
                data.getRuleId(),
                newRisk.getId(),
                env.replaceVars(JobUtils.unBox(data.getUrl(), "")),
                JobUtils.unBox(data.getUrlRegex()),
                env.replaceVars(JobUtils.unBox(data.getParameter(), "")),
                JobUtils.unBox(data.getParameterRegex()),
                data.getAttack(),
                JobUtils.unBox(data.getAttackRegex()),
                data.getEvidence(),
                JobUtils.unBox(data.getEvidenceRegex()),
                true);
    }

    @Override
    public String getTemplateDataMin() {
        return getResourceAsString(getName() + "-min.yaml");
    }

    @Override
    public String getTemplateDataMax() {
        return getResourceAsString(getName() + "-max.yaml");
    }

    private String getResourceAsString(String name) {
        try (InputStream in =
                ExtensionAlertFilters.class.getResourceAsStream(RESOURCES_DIR + name)) {
            return new BufferedReader(new InputStreamReader(in))
                            .lines()
                            .collect(Collectors.joining("\n"))
                    + "\n";
        } catch (Exception e) {
            CommandLine.error(
                    Constant.messages.getString("automation.error.nofile", RESOURCES_DIR + name));
        }
        return "";
    }

    @Override
    public Order getOrder() {
        return Order.CONFIGS;
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
    public void showDialog() {
        new AlertFilterJobDialog(this).setVisible(true);
    }

    @Override
    public String getSummary() {
        return Constant.messages.getString(
                "alertFilters.automation.dialog.summary", getAlertFilterCount());
    }

    @Override
    public Data getData() {
        return data;
    }

    @Override
    public Parameters getParameters() {
        return getData().getParameters();
    }

    protected int getAlertFilterCount() {
        if (this.getData().getAlertFilters() == null) {
            return 0;
        }
        return this.getData().getAlertFilters().size();
    }

    public static class Data extends JobData {
        private List<AlertFilterData> alertFilters;
        private Parameters parameters = new Parameters();

        public Data(AutomationJob job) {
            super(job);
        }

        public Parameters getParameters() {
            return parameters;
        }

        public List<AlertFilterData> getAlertFilters() {
            return alertFilters;
        }

        public void setAlertFilters(List<AlertFilterData> alertFilters) {
            this.alertFilters = alertFilters;
        }

        public void addAlertFilters(AlertFilterData alertFilter) {
            if (alertFilters == null) {
                alertFilters = new ArrayList<>();
            }
            this.alertFilters.add(alertFilter);
        }
    }

    public static class Parameters extends AutomationData {
        private Boolean deleteGlobalAlerts;

        public Boolean getDeleteGlobalAlerts() {
            return deleteGlobalAlerts;
        }

        public void setDeleteGlobalAlerts(Boolean deleteGlobalAlerts) {
            this.deleteGlobalAlerts = deleteGlobalAlerts;
        }
    }

    public static class AlertFilterData extends AutomationData {
        private int ruleId;
        private String ruleName;
        private String context;
        private String newRisk;
        private String parameter;
        private Boolean parameterRegex;
        private String url;
        private Boolean urlRegex;
        private String attack;
        private Boolean attackRegex;
        private String evidence;
        private Boolean evidenceRegex;

        public int getRuleId() {
            return ruleId;
        }

        public void setRuleId(int ruleId) {
            this.ruleId = ruleId;
        }

        public String getRuleName() {
            return ruleName;
        }

        public void setRuleName(String ruleName) {
            this.ruleName = ruleName;
        }

        public String getContext() {
            return context;
        }

        public void setContext(String context) {
            this.context = context;
        }

        public String getNewRisk() {
            return newRisk;
        }

        public void setNewRisk(String newRisk) {
            this.newRisk = newRisk;
        }

        public String getParameter() {
            return parameter;
        }

        public void setParameter(String parameter) {
            this.parameter = parameter;
        }

        public Boolean getParameterRegex() {
            return parameterRegex;
        }

        public void setParameterRegex(Boolean isParameterRegex) {
            this.parameterRegex = isParameterRegex;
        }

        public String getUrl() {
            return url;
        }

        public void setUrl(String url) {
            this.url = url;
        }

        public Boolean getUrlRegex() {
            return urlRegex;
        }

        public void setUrlRegex(Boolean isUrlRegex) {
            this.urlRegex = isUrlRegex;
        }

        public String getAttack() {
            return attack;
        }

        public void setAttack(String attack) {
            this.attack = attack;
        }

        public Boolean getAttackRegex() {
            return attackRegex;
        }

        public void setAttackRegex(Boolean isAttackRegex) {
            this.attackRegex = isAttackRegex;
        }

        public String getEvidence() {
            return evidence;
        }

        public void setEvidence(String evidence) {
            this.evidence = evidence;
        }

        public Boolean getEvidenceRegex() {
            return evidenceRegex;
        }

        public void setEvidenceRegex(Boolean isEvidenceRegex) {
            this.evidenceRegex = isEvidenceRegex;
        }
    }
}
