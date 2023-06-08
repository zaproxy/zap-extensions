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
package org.zaproxy.zap.extension.spiderAjax.automation;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.automation.AutomationData;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.ContextWrapper;
import org.zaproxy.addon.automation.JobResultData;
import org.zaproxy.addon.automation.jobs.JobData;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.addon.automation.jobs.PassiveScanJobResultData;
import org.zaproxy.addon.automation.jobs.PassiveScanJobResultData.RuleData;
import org.zaproxy.addon.automation.tests.AbstractAutomationTest;
import org.zaproxy.addon.automation.tests.AutomationStatisticTest;
import org.zaproxy.addon.commonlib.Constants;
import org.zaproxy.zap.extension.spiderAjax.AjaxSpiderParam;
import org.zaproxy.zap.extension.spiderAjax.AjaxSpiderParamElem;
import org.zaproxy.zap.extension.spiderAjax.AjaxSpiderTarget;
import org.zaproxy.zap.extension.spiderAjax.ExtensionAjax;
import org.zaproxy.zap.extension.spiderAjax.SpiderListener;
import org.zaproxy.zap.extension.spiderAjax.SpiderThread;
import org.zaproxy.zap.extension.spiderAjax.internal.ExcludedElement;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.utils.Stats;

public class AjaxSpiderJob extends AutomationJob {

    private static final String JOB_NAME = "spiderAjax";
    private static final String OPTIONS_METHOD_NAME = "getAjaxSpiderParam";

    private static final String PARAM_CONTEXT = "context";
    private static final String PARAM_URL = "url";
    private static final String PARAM_USER = "user";
    private static final String PARAM_IN_SCOPE_ONLY = "inScopeOnly";
    private static final String PARAM_ONLY_RUN_IF_MODERN = "runOnlyIfModern";
    private static final String PARAM_ELEMENTS = "elements";
    private static final String PARAM_FAIL_IF_LESS_URLS = "failIfFoundUrlsLessThan";
    private static final String PARAM_WARN_IF_LESS_URLS = "warnIfFoundUrlsLessThan";
    private static final String PARAM_EXCLUDED_ELEMENTS = "excludedElements";

    private static final int MODERN_WEB_DETECTION_RULE_ID = 10109;

    private ExtensionAjax extSpider;

    private Data data;
    private Parameters parameters = new Parameters();

    public AjaxSpiderJob() {
        this.data = new Data(this, parameters);
    }

    private ExtensionAjax getExtSpider() {
        if (extSpider == null) {
            extSpider =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionAjax.class);
        }
        return extSpider;
    }

    @Override
    public void verifyParameters(AutomationProgress progress) {
        Map<?, ?> jobData = this.getJobData();
        if (jobData == null) {
            return;
        }
        Map<?, ?> parametersData = (Map<?, ?>) jobData.get("parameters");
        JobUtils.applyParamsToObject(
                parametersData,
                this.parameters,
                this.getName(),
                new String[] {PARAM_EXCLUDED_ELEMENTS},
                progress);

        readExcludedElements(progress, parametersData);

        if (this.getParameters().getWarnIfFoundUrlsLessThan() != null
                || this.getParameters().getFailIfFoundUrlsLessThan() != null) {
            progress.warn(
                    Constant.messages.getString(
                            "automation.error.spider.failIfUrlsLessThan.deprecated",
                            getName(),
                            "automation.spiderAjax.urls.added"));
        }
    }

    @SuppressWarnings("unchecked")
    private void readExcludedElements(AutomationProgress progress, Map<?, ?> parametersData) {
        if (parametersData == null) {
            return;
        }

        try {
            var eeData = (List<Map<String, ?>>) parametersData.get(PARAM_EXCLUDED_ELEMENTS);
            if (eeData != null && !eeData.isEmpty()) {
                var excludedElements = JobMapper.INSTANCE.toDtoFromPlan(eeData);
                var validatedElements = new ArrayList<ExcludedElementAuto>();
                excludedElements.forEach(
                        e -> {
                            if (validate(progress, e, validatedElements)) {
                                validatedElements.add(e);
                            }
                        });

                getParameters().setExcludedElements(validatedElements);
            }
        } catch (Exception e) {
            progress.error(
                    Constant.messages.getString(
                            "spiderajax.automation.error.excludedelements.format", getName(), e));
        }
    }

    private boolean validate(
            AutomationProgress progress,
            ExcludedElement element,
            List<ExcludedElementAuto> elements) {
        ExcludedElement.ValidationResult result = ExcludedElement.validate(null, element, elements);

        switch (result) {
            case EMPTY_DESCRIPTION:
                progress.error(
                        Constant.messages.getString(
                                "spiderajax.automation.error.excludedelements.description",
                                getName()));
                break;

            case EMPTY_ELEMENT:
                progress.error(
                        Constant.messages.getString(
                                "spiderajax.automation.error.excludedelements.element",
                                getName(),
                                element.getDescription()));
                break;

            case MISSING_DATA:
                progress.error(
                        Constant.messages.getString(
                                "spiderajax.automation.error.excludedelements.data",
                                getName(),
                                element.getDescription()));
                break;

            case MISSING_ATTRIBUTE_FIELD:
                progress.error(
                        Constant.messages.getString(
                                "spiderajax.automation.error.excludedelements.attribute",
                                getName(),
                                element.getDescription()));
                break;

            case DUPLICATED:
                progress.error(
                        Constant.messages.getString(
                                "spiderajax.automation.error.excludedelements.duplicated",
                                getName(),
                                element.getDescription()));
                break;

            case VALID:
            default:
                break;
        }

        return result == ExcludedElement.ValidationResult.VALID;
    }

    @Override
    public void applyParameters(AutomationProgress progress) {
        JobUtils.applyObjectToObject(
                this.parameters,
                JobUtils.getJobOptions(this, progress),
                this.getName(),
                new String[] {
                    PARAM_CONTEXT,
                    PARAM_URL,
                    PARAM_USER,
                    PARAM_IN_SCOPE_ONLY,
                    PARAM_ELEMENTS,
                    PARAM_ONLY_RUN_IF_MODERN,
                    PARAM_FAIL_IF_LESS_URLS,
                    PARAM_WARN_IF_LESS_URLS,
                    PARAM_EXCLUDED_ELEMENTS
                },
                progress,
                this.getPlan().getEnv());

        if (!JobUtils.unBox(this.parameters.clickDefaultElems)
                && this.parameters.getElements() != null) {
            List<AjaxSpiderParamElem> elems = new ArrayList<>(this.parameters.getElements().size());
            this.parameters.getElements().forEach(e -> elems.add(new AjaxSpiderParamElem(e)));
            this.getExtSpider().getAjaxSpiderParam().setElems(elems);
        }

        ContextWrapper context = getContextWrapper(getPlan().getEnv(), progress);
        if (context != null) {
            getExtSpider()
                    .getContextDataManager()
                    .setExcludedElements(
                            context.getContext(),
                            JobMapper.INSTANCE.toModel(getParameters().getExcludedElements()));
        }
    }

    @Override
    public Map<String, String> getCustomConfigParameters() {
        Map<String, String> map = super.getCustomConfigParameters();
        map.put(PARAM_CONTEXT, "");
        map.put(PARAM_URL, "");
        map.put(PARAM_USER, "");
        map.put(PARAM_ONLY_RUN_IF_MODERN, Boolean.FALSE.toString());
        return map;
    }

    @Override
    public boolean supportsMonitorTests() {
        return true;
    }

    @Override
    public void runJob(AutomationEnvironment env, AutomationProgress progress) {

        ContextWrapper context = getContextWrapper(env, progress);
        if (context == null) {
            return;
        }

        User user = this.getUser(this.getParameters().getUser(), progress);

        String uriStr = this.getParameters().getUrl();
        if (StringUtils.isEmpty(uriStr)) {
            uriStr = context.getUrls().get(0);
        }
        uriStr = env.replaceVars(uriStr);
        URI uri = null;
        try {
            uri = new URI(uriStr);
        } catch (Exception e1) {
            progress.error(Constant.messages.getString("automation.error.context.badurl", uriStr));
            return;
        }

        if (Boolean.TRUE.equals(this.getParameters().getRunOnlyIfModern())) {
            JobResultData resultData = progress.getJobResultData(PassiveScanJobResultData.KEY);
            if (resultData == null) {
                // They havnt run the passive scan wait job
                progress.warn(
                        Constant.messages.getString("spiderajax.automation.error.nopscanresults"));
            } else if (resultData instanceof PassiveScanJobResultData) {
                PassiveScanJobResultData pscanResultData = (PassiveScanJobResultData) resultData;

                List<RuleData> modernRuleData =
                        pscanResultData.getAllRuleData().stream()
                                .filter(r -> r.getId() == MODERN_WEB_DETECTION_RULE_ID)
                                .collect(Collectors.toList());

                if (modernRuleData.isEmpty()
                        || AlertThreshold.OFF.equals(modernRuleData.get(0).getThreshold())) {
                    // Rule is not present or turned off
                    progress.warn(
                            Constant.messages.getString(
                                    "spiderajax.automation.error.nomodernrule"));
                } else if (resultData.getAlertData(MODERN_WEB_DETECTION_RULE_ID) == null) {
                    progress.info(
                            Constant.messages.getString("spiderajax.automation.info.notmodern"));
                    return;
                } else {
                    progress.info(Constant.messages.getString("spiderajax.automation.info.modern"));
                }
            } else {
                progress.error(
                        Constant.messages.getString(
                                "spiderajax.automation.error.badresultdata",
                                resultData.getClass().getCanonicalName()));
            }
        }

        AjaxSpiderTarget.Builder targetBuilder =
                AjaxSpiderTarget.newBuilder(getExtSpider())
                        .setContext(context.getContext())
                        .setUser(user)
                        .setInScopeOnly(JobUtils.unBox(this.getParameters().getInScopeOnly()))
                        .setOptions(getExtSpider().getAjaxSpiderParam())
                        .setStartUri(uri)
                        .setSubtreeOnly(false);

        AjaxSpiderTarget target = targetBuilder.build();
        JobSpiderListener listener = new JobSpiderListener();

        SpiderThread spiderThread =
                getExtSpider()
                        .createSpiderThread(
                                "Auto - " + getExtSpider().createDisplayName(target),
                                target,
                                listener);
        new Thread(spiderThread, "ZAP-AjaxSpiderAuto").start();

        long endTime = Long.MAX_VALUE;
        if (JobUtils.unBox(this.getParameters().getMaxDuration()) > 0) {
            // The spider should stop, if it doesnt we will stop it (after a few seconds leeway)
            endTime =
                    System.currentTimeMillis()
                            + TimeUnit.MINUTES.toMillis(this.getParameters().getMaxDuration())
                            + TimeUnit.SECONDS.toMillis(5);
        }

        // Wait for the ajax spider to finish
        boolean forceStop = false;
        int numUrlsFound = 0;
        int lastCount = 0;

        while (true) {
            this.sleep(500);

            numUrlsFound = listener.getMessagesFound();
            Stats.incCounter("spiderAjax.urls.added", numUrlsFound - lastCount);
            lastCount = numUrlsFound;

            if (!spiderThread.isRunning()) {
                break;
            }
            if (!this.runMonitorTests(progress) || System.currentTimeMillis() > endTime) {
                forceStop = true;
                break;
            }
        }
        if (forceStop) {
            spiderThread.stopSpider();
            progress.info(Constant.messages.getString("automation.info.jobstopped", getType()));
        }

        progress.info(
                Constant.messages.getString(
                        "automation.info.urlsfound", this.getType(), numUrlsFound));
    }

    private ContextWrapper getContextWrapper(
            AutomationEnvironment env, AutomationProgress progress) {
        String contextName = this.getParameters().getContext();
        if (contextName == null) {
            return env.getDefaultContextWrapper();
        }

        ContextWrapper wrapper = env.getContextWrapper(contextName);
        if (wrapper != null) {
            return wrapper;
        }

        progress.error(
                Constant.messages.getString("automation.error.context.unknown", contextName));
        return null;
    }

    @Override
    public boolean isExcludeParam(String param) {
        switch (param) {
            case "confirmRemoveAllowedResource":
            case "confirmRemoveDomainAlwaysInScope":
            case "confirmRemoveElem":
            case "showAdvancedDialog":
                return true;
            default:
                return false;
        }
    }

    @Override
    public String getTemplateDataMin() {
        return ExtensionAjaxAutomation.getResourceAsString(this.getType() + "-min.yaml");
    }

    @Override
    public String getTemplateDataMax() {
        return ExtensionAjaxAutomation.getResourceAsString(this.getType() + "-max.yaml");
    }

    @Override
    public Order getOrder() {
        return Order.LAST_EXPLORE;
    }

    @Override
    public Object getParamMethodObject() {
        return this.getExtSpider();
    }

    @Override
    public String getParamMethodName() {
        return OPTIONS_METHOD_NAME;
    }

    @Override
    public String getType() {
        return JOB_NAME;
    }

    private class JobSpiderListener implements SpiderListener {
        public int messagesFound = 0;

        public int getMessagesFound() {
            return this.messagesFound;
        }

        @Override
        public void spiderStarted() {}

        @Override
        public void foundMessage(
                HistoryReference historyReference, HttpMessage httpMessage, ResourceState state) {
            messagesFound++;
        }

        @Override
        public void spiderStopped() {}
    }

    @Override
    public void showDialog() {
        new AjaxSpiderJobDialog(this).setVisible(true);
    }

    @Override
    public int addDefaultTests(AutomationProgress progress) {
        ContextWrapper context = getContextWrapper(getEnv(), progress);
        if (context != null) {
            getParameters()
                    .setExcludedElements(
                            JobMapper.INSTANCE.toDto(
                                    getExtSpider()
                                            .getContextDataManager()
                                            .getExcludedElements(context.getContext())));
        }

        AutomationStatisticTest test =
                new AutomationStatisticTest(
                        "spiderAjax.urls.added",
                        Constant.messages.getString(
                                "spiderajax.automation.tests.stats.defaultname", 100),
                        AutomationStatisticTest.Operator.GREATER_OR_EQUAL.getSymbol(),
                        100,
                        AbstractAutomationTest.OnFail.INFO.name(),
                        this,
                        progress);
        this.addTest(test);
        return 1;
    }

    @Override
    public String getSummary() {
        String context = this.getParameters().getContext();
        if (StringUtils.isEmpty(context)) {
            context = Constant.messages.getString("spiderajax.automation.default");
        }
        return Constant.messages.getString(
                "spiderajax.automation.dialog.summary",
                context,
                JobUtils.unBox(this.getParameters().getUrl(), "''"));
    }

    @Override
    public Data getData() {
        return data;
    }

    @Override
    public Parameters getParameters() {
        return parameters;
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
        private String context;
        private String user;
        private String url;
        private Integer maxDuration = AjaxSpiderParam.DEFAULT_MAX_DURATION;
        private Integer maxCrawlDepth = AjaxSpiderParam.DEFAULT_MAX_CRAWL_DEPTH;
        private Integer numberOfBrowsers = Constants.getDefaultThreadCount();

        private String browserId;
        private Integer maxCrawlStates;
        private Integer eventWait;
        private Integer reloadWait;
        private Boolean clickDefaultElems;
        private Boolean clickElemsOnce;
        private Boolean randomInputs;
        private Boolean inScopeOnly = Boolean.TRUE;

        private Boolean runOnlyIfModern;

        private List<String> elements;

        @JsonInclude(JsonInclude.Include.NON_EMPTY)
        private List<ExcludedElementAuto> excludedElements = List.of();

        // These 2 fields are deprecated
        private Boolean failIfFoundUrlsLessThan;
        private Boolean warnIfFoundUrlsLessThan;

        public Parameters() {}

        public String getContext() {
            return context;
        }

        public void setContext(String context) {
            this.context = context;
        }

        public String getUser() {
            return user;
        }

        public void setUser(String user) {
            this.user = user;
        }

        public String getUrl() {
            return url;
        }

        public void setUrl(String url) {
            this.url = url;
        }

        public Integer getMaxDuration() {
            return maxDuration;
        }

        public void setMaxDuration(Integer maxDuration) {
            this.maxDuration = maxDuration;
        }

        public Integer getMaxCrawlDepth() {
            return maxCrawlDepth;
        }

        public void setMaxCrawlDepth(Integer maxCrawlDepth) {
            this.maxCrawlDepth = maxCrawlDepth;
        }

        public Integer getNumberOfBrowsers() {
            return numberOfBrowsers;
        }

        public void setNumberOfBrowsers(Integer numberOfBrowsers) {
            this.numberOfBrowsers = numberOfBrowsers;
        }

        public String getBrowserId() {
            return browserId;
        }

        public void setBrowserId(String browserId) {
            this.browserId = browserId;
        }

        public Boolean getClickDefaultElems() {
            return clickDefaultElems;
        }

        public void setClickDefaultElems(Boolean clickDefaultElems) {
            this.clickDefaultElems = clickDefaultElems;
        }

        public Boolean getClickElemsOnce() {
            return clickElemsOnce;
        }

        public void setClickElemsOnce(Boolean clickElemsOnce) {
            this.clickElemsOnce = clickElemsOnce;
        }

        public Integer getEventWait() {
            return eventWait;
        }

        public void setEventWait(Integer eventWait) {
            this.eventWait = eventWait;
        }

        public Integer getMaxCrawlStates() {
            return maxCrawlStates;
        }

        public void setMaxCrawlStates(Integer maxCrawlStates) {
            this.maxCrawlStates = maxCrawlStates;
        }

        public Boolean getRandomInputs() {
            return randomInputs;
        }

        public void setRandomInputs(Boolean randomInputs) {
            this.randomInputs = randomInputs;
        }

        public Boolean getInScopeOnly() {
            return inScopeOnly;
        }

        public void setInScopeOnly(Boolean inScopeOnly) {
            this.inScopeOnly = inScopeOnly;
        }

        public Integer getReloadWait() {
            return reloadWait;
        }

        public void setReloadWait(Integer reloadWait) {
            this.reloadWait = reloadWait;
        }

        public Boolean getRunOnlyIfModern() {
            return runOnlyIfModern;
        }

        public void setRunOnlyIfModern(Boolean runOnlyIfModern) {
            this.runOnlyIfModern = runOnlyIfModern;
        }

        public Boolean getFailIfFoundUrlsLessThan() {
            return failIfFoundUrlsLessThan;
        }

        public List<String> getElements() {
            if (JobUtils.unBox(this.clickDefaultElems)) {
                return null;
            }
            return elements;
        }

        public void setExcludedElements(List<ExcludedElementAuto> excludedElements) {
            this.excludedElements = Objects.requireNonNullElse(excludedElements, List.of());
        }

        public List<ExcludedElementAuto> getExcludedElements() {
            return excludedElements;
        }

        public void setElements(List<String> elements) {
            this.elements = elements;
        }

        public void setFailIfFoundUrlsLessThan(Boolean failIfFoundUrlsLessThan) {
            this.failIfFoundUrlsLessThan = failIfFoundUrlsLessThan;
        }

        public Boolean getWarnIfFoundUrlsLessThan() {
            return warnIfFoundUrlsLessThan;
        }

        public void setWarnIfFoundUrlsLessThan(Boolean warnIfFoundUrlsLessThan) {
            this.warnIfFoundUrlsLessThan = warnIfFoundUrlsLessThan;
        }
    }
}
