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

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.apache.commons.lang.StringUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.automation.AutomationData;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.ContextWrapper;
import org.zaproxy.addon.automation.jobs.JobData;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.addon.automation.tests.AbstractAutomationTest;
import org.zaproxy.addon.automation.tests.AutomationStatisticTest;
import org.zaproxy.zap.extension.spiderAjax.AjaxSpiderTarget;
import org.zaproxy.zap.extension.spiderAjax.ExtensionAjax;
import org.zaproxy.zap.extension.spiderAjax.SpiderListener;
import org.zaproxy.zap.extension.spiderAjax.SpiderThread;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.utils.Stats;

public class AjaxSpiderJob extends AutomationJob {

    private static final String JOB_NAME = "spiderAjax";
    private static final String OPTIONS_METHOD_NAME = "getAjaxSpiderParam";

    private static final String PARAM_CONTEXT = "context";
    private static final String PARAM_URL = "url";
    private static final String PARAM_FAIL_IF_LESS_URLS = "failIfFoundUrlsLessThan";
    private static final String PARAM_WARN_IF_LESS_URLS = "warnIfFoundUrlsLessThan";

    private ExtensionAjax extSpider;

    private boolean inScopeOnly = true;

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
        JobUtils.applyParamsToObject(
                (LinkedHashMap<?, ?>) jobData.get("parameters"),
                this.parameters,
                this.getName(),
                null,
                progress);
        if (this.getParameters().getWarnIfFoundUrlsLessThan() != null
                || this.getParameters().getFailIfFoundUrlsLessThan() != null) {
            progress.warn(
                    Constant.messages.getString(
                            "automation.error.spider.failIfUrlsLessThan.deprecated",
                            getName(),
                            "automation.spiderAjax.urls.added"));
        }
    }

    @Override
    public void applyParameters(AutomationProgress progress) {
        JobUtils.applyObjectToObject(
                this.parameters,
                JobUtils.getJobOptions(this, progress),
                this.getName(),
                new String[] {
                    PARAM_CONTEXT, PARAM_URL, PARAM_FAIL_IF_LESS_URLS, PARAM_WARN_IF_LESS_URLS
                },
                progress,
                this.getPlan().getEnv());
    }

    @Override
    public Map<String, String> getCustomConfigParameters() {
        Map<String, String> map = super.getCustomConfigParameters();
        map.put(PARAM_CONTEXT, "");
        map.put(PARAM_URL, "");
        return map;
    }

    @Override
    public boolean supportsMonitorTests() {
        return true;
    }

    @Override
    public void runJob(AutomationEnvironment env, AutomationProgress progress) {

        ContextWrapper context;
        String contextName = this.getParameters().getContext();
        if (contextName != null) {
            context = env.getContextWrapper(contextName);
            if (context == null) {
                progress.error(
                        Constant.messages.getString(
                                "automation.error.context.unknown", contextName));
                return;
            }
        } else {
            context = env.getDefaultContextWrapper();
        }
        User user = this.getUser(this.getParameters().getUser(), progress);

        String uriStr = this.getParameters().getUrl();
        if (uriStr == null) {
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

        AjaxSpiderTarget.Builder targetBuilder =
                AjaxSpiderTarget.newBuilder(Model.getSingleton().getSession())
                        .setContext(context.getContext())
                        .setUser(user)
                        .setInScopeOnly(inScopeOnly)
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

    /**
     * Sets whether the ajax spider should only load URLs that are in scope - only intended to use
     * for testing
     *
     * @param inScopeOnly whether the ajax spider should only load URLs that are in scope
     */
    protected void setInScopeOnly(boolean inScopeOnly) {
        this.inScopeOnly = inScopeOnly;
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
        private Integer maxDuration;
        private Integer maxCrawlDepth;
        private Integer numberOfBrowsers;

        private String browserId;
        private Integer maxCrawlStates;
        private Integer eventWait;
        private Integer reloadWait;
        private Boolean clickDefaultElems;
        private Boolean clickElemsOnce;
        private Boolean randomInputs;

        // These 2 fields are deprecated
        private Boolean failIfFoundUrlsLessThan;
        private Boolean warnIfFoundUrlsLessThan;

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

        public Integer getReloadWait() {
            return reloadWait;
        }

        public void setReloadWait(Integer reloadWait) {
            this.reloadWait = reloadWait;
        }

        public Boolean getFailIfFoundUrlsLessThan() {
            return failIfFoundUrlsLessThan;
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
