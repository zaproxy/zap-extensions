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
package org.zaproxy.addon.spider.automation;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import org.apache.commons.httpclient.URI;
import org.apache.commons.lang.StringUtils;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.ConnectionParam;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.addon.automation.AutomationData;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.ContextWrapper;
import org.zaproxy.addon.automation.jobs.JobData;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.addon.automation.tests.AbstractAutomationTest;
import org.zaproxy.addon.automation.tests.AutomationStatisticTest;
import org.zaproxy.addon.spider.ExtensionSpider2;
import org.zaproxy.addon.spider.SpiderScan;
import org.zaproxy.zap.model.Target;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.utils.Stats;
import org.zaproxy.zap.utils.ThreadUtils;

public class SpiderJob extends AutomationJob {

    public static final String JOB_NAME = "spider";
    private static final String OPTIONS_METHOD_NAME = "getSpiderParam";

    private static final String URLS_ADDED_STATS_KEY = "automation.spider.urls.added";

    private static final String PARAM_CONTEXT = "context";
    private static final String PARAM_URL = "url";
    private static final String PARAM_FAIL_IF_LESS_URLS = "failIfFoundUrlsLessThan";
    private static final String PARAM_WARN_IF_LESS_URLS = "warnIfFoundUrlsLessThan";

    private ExtensionSpider2 extSpider;

    private Data data;
    private Parameters parameters = new Parameters();

    private UrlRequester urlRequester = new UrlRequester(this.getName());

    public SpiderJob() {
        this.data = new Data(this, parameters);
    }

    @Override
    public String getTemplateDataMin() {
        return getResourceAsString(getType() + "-min.yaml");
    }

    private static String getResourceAsString(String fileName) {
        try (InputStream in = SpiderJob.class.getResourceAsStream(fileName)) {
            return new BufferedReader(new InputStreamReader(in))
                            .lines()
                            .collect(Collectors.joining("\n"))
                    + "\n";
        } catch (Exception e) {
            CommandLine.error(
                    Constant.messages.getString("spider.automation.error.nofile", fileName));
        }
        return "";
    }

    @Override
    public String getTemplateDataMax() {
        return getResourceAsString(getType() + "-max.yaml");
    }

    private ExtensionSpider2 getExtSpider() {
        if (extSpider == null) {
            extSpider =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionSpider2.class);
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

        this.verifyUser(this.getParameters().getUser(), progress);

        if (this.getParameters().getWarnIfFoundUrlsLessThan() != null
                || this.getParameters().getFailIfFoundUrlsLessThan() != null) {
            progress.warn(
                    Constant.messages.getString(
                            "spider.automation.error.failIfUrlsLessThan.deprecated",
                            getName(),
                            URLS_ADDED_STATS_KEY));
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

        getExtSpider().setPanelSwitch(false);

        ContextWrapper context;
        if (parameters.getContext() != null) {
            context = env.getContextWrapper(parameters.getContext());
            if (context == null) {
                progress.error(
                        Constant.messages.getString(
                                "automation.error.context.unknown", parameters.getContext()));
                return;
            }
        } else {
            context = env.getDefaultContextWrapper();
        }
        URI uri = null;
        String urlStr = parameters.getUrl();
        try {
            if (urlStr != null) {
                urlStr = env.replaceVars(urlStr);
                uri = new URI(urlStr, true);
            }
        } catch (Exception e1) {
            progress.error(Constant.messages.getString("automation.error.context.badurl", urlStr));
            return;
        }
        User user = this.getUser(this.getParameters().getUser(), progress);

        // Request all specified URLs
        for (String u : context.getUrls()) {
            urlStr = env.replaceVars(u);
            progress.info(
                    Constant.messages.getString("automation.info.requrl", this.getName(), urlStr));
            this.urlRequester.requestUrl(urlStr, user, progress);
        }

        if (env.isTimeToQuit()) {
            // Failed to access one of the URLs
            return;
        }

        Target target = new Target(context.getContext());
        target.setRecurse(true);
        List<Object> contextSpecificObjects = new ArrayList<>();
        if (uri != null) {
            contextSpecificObjects.add(uri);
        }

        int scanId = this.getExtSpider().startScan(target, user, contextSpecificObjects.toArray());

        long endTime = Long.MAX_VALUE;
        if (parameters.getMaxDuration() != null && parameters.getMaxDuration() > 0) {
            // The spider should stop, if it doesnt we will stop it (after a few seconds leeway)
            endTime =
                    System.currentTimeMillis()
                            + TimeUnit.MINUTES.toMillis(parameters.getMaxDuration())
                            + TimeUnit.SECONDS.toMillis(5);
        }

        // Wait for the spider to finish
        SpiderScan scan;
        boolean forceStop = false;
        int numUrlsFound = 0;
        int lastCount = 0;

        while (true) {
            this.sleep(500);

            scan = this.getExtSpider().getScan(scanId);
            numUrlsFound = scan.getNumberOfURIsFound();
            Stats.incCounter(URLS_ADDED_STATS_KEY, numUrlsFound - lastCount);
            lastCount = numUrlsFound;

            if (scan.isStopped()) {
                break;
            }
            if (!this.runMonitorTests(progress) || System.currentTimeMillis() > endTime) {
                forceStop = true;
                break;
            }
        }
        if (forceStop) {
            this.getExtSpider().stopScan(scanId);
            progress.info(Constant.messages.getString("automation.info.jobstopped", getType()));
        }
        numUrlsFound = scan.getNumberOfURIsFound();

        progress.info(
                Constant.messages.getString(
                        "automation.info.urlsfound", this.getName(), numUrlsFound));

        getExtSpider().setPanelSwitch(true);
    }

    /**
     * Only for use by unit tests
     *
     * @param urlRequester the UrlRequester to use
     */
    protected void setUrlRequester(UrlRequester urlRequester) {
        this.urlRequester = urlRequester;
    }

    @Override
    public boolean isExcludeParam(String param) {
        switch (param) {
            case "confirmRemoveDomainAlwaysInScope":
            case "confirmRemoveIrrelevantParameter":
            case "maxScansInUI":
            case "showAdvancedDialog":
            case "skipURLString":
                return true;
            default:
                return false;
        }
    }

    @Override
    public Parameters getParameters() {
        return parameters;
    }

    @Override
    public void showDialog() {
        new SpiderJobDialog(this).setVisible(true);
    }

    @Override
    public String getSummary() {
        String context = this.getParameters().getContext();
        if (StringUtils.isEmpty(context)) {
            context = Constant.messages.getString("automation.dialog.default");
        }
        return Constant.messages.getString(
                "spider.automation.dialog.summary",
                context,
                JobUtils.unBox(this.getParameters().getUrl(), "''"));
    }

    @Override
    public String getType() {
        return JOB_NAME;
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
    public int addDefaultTests(AutomationProgress progress) {
        AutomationStatisticTest test =
                new AutomationStatisticTest(
                        URLS_ADDED_STATS_KEY,
                        Constant.messages.getString(
                                "spider.automation.dialog.tests.stats.defaultname", 100),
                        AutomationStatisticTest.Operator.GREATER_OR_EQUAL.getSymbol(),
                        100,
                        AbstractAutomationTest.OnFail.INFO.name(),
                        this,
                        progress);
        this.addTest(test);
        return 1;
    }

    public static class UrlRequester {

        private final HttpSender httpSender;
        private final String requester;

        public UrlRequester(String requester) {
            this.requester = requester;
            httpSender =
                    new HttpSender(
                            Model.getSingleton().getOptionsParam().getConnectionParam(),
                            true,
                            HttpSender.SPIDER_INITIATOR);
        }

        public void requestUrl(String url, User user, AutomationProgress progress) {
            // Request the URL
            try {
                final HttpMessage msg = new HttpMessage(new URI(url, true));

                if (user != null) {
                    msg.setRequestingUser(user);
                }

                httpSender.sendAndReceive(msg, true);

                if (msg.getResponseHeader().getStatusCode() != HttpStatusCode.OK) {
                    progress.error(
                            Constant.messages.getString(
                                    "spider.automation.error.url.notok",
                                    requester,
                                    url,
                                    msg.getResponseHeader().getStatusCode()));
                    return;
                }

                ExtensionHistory extHistory =
                        Control.getSingleton()
                                .getExtensionLoader()
                                .getExtension(ExtensionHistory.class);
                extHistory.addHistory(msg, HistoryReference.TYPE_SPIDER);

                ThreadUtils.invokeAndWait(
                        () ->
                                // Needs to be done on the EDT
                                Model.getSingleton()
                                        .getSession()
                                        .getSiteTree()
                                        .addPath(msg.getHistoryRef()));
            } catch (UnknownHostException e1) {
                ConnectionParam connectionParam =
                        Model.getSingleton().getOptionsParam().getConnectionParam();
                if (connectionParam.isUseProxyChain()
                        && connectionParam.getProxyChainName().equalsIgnoreCase(e1.getMessage())) {
                    progress.error(
                            Constant.messages.getString(
                                    "spider.automation.error.url.badhost.proxychain",
                                    requester,
                                    url,
                                    e1.getMessage()));
                } else {
                    progress.error(
                            Constant.messages.getString(
                                    "spider.automation.error.url.badhost",
                                    requester,
                                    url,
                                    e1.getMessage()));
                }
            } catch (Exception e1) {
                progress.error(
                        Constant.messages.getString(
                                "spider.automation.error.url.failed",
                                requester,
                                url,
                                e1.getMessage()));
            }
        }
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
    }

    public static class Parameters extends AutomationData {
        private String context;
        private String user;
        private String url;
        private Integer maxDuration;
        private Integer maxDepth;
        private Integer maxChildren;
        private Boolean acceptCookies;
        private Boolean handleODataParametersVisited;
        private String handleParameters;
        private Integer maxParseSizeBytes;
        private Boolean parseComments;
        private Boolean parseGit;
        private Boolean parseRobotsTxt;
        private Boolean parseSitemapXml;
        private Boolean parseSVNEntries;
        private Boolean postForm;
        private Boolean processForm;
        private Integer requestWaitTime;
        private Boolean sendRefererHeader;
        private Integer threadCount;
        private String userAgent;
        // These 2 fields are deprecated
        private Boolean failIfFoundUrlsLessThan;
        private Boolean warnIfFoundUrlsLessThan;

        public Parameters() {
            super();
        }

        public void setMaxDuration(int maxDuration) {
            this.maxDuration = maxDuration;
        }

        public Integer getMaxDuration() {
            return maxDuration;
        }

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

        public Integer getMaxDepth() {
            return maxDepth;
        }

        public void setMaxDepth(Integer maxDepth) {
            this.maxDepth = maxDepth;
        }

        public Integer getMaxChildren() {
            return maxChildren;
        }

        public void setMaxChildren(Integer maxChildren) {
            this.maxChildren = maxChildren;
        }

        public Boolean getAcceptCookies() {
            return acceptCookies;
        }

        public void setAcceptCookies(Boolean acceptCookies) {
            this.acceptCookies = acceptCookies;
        }

        public Boolean getHandleODataParametersVisited() {
            return handleODataParametersVisited;
        }

        public void setHandleODataParametersVisited(Boolean handleODataParametersVisited) {
            this.handleODataParametersVisited = handleODataParametersVisited;
        }

        public void setMaxDuration(Integer maxDuration) {
            this.maxDuration = maxDuration;
        }

        public String getHandleParameters() {
            return handleParameters;
        }

        public void setHandleParameters(String handleParameters) {
            this.handleParameters = handleParameters;
        }

        public Integer getMaxParseSizeBytes() {
            return maxParseSizeBytes;
        }

        public void setMaxParseSizeBytes(Integer maxParseSizeBytes) {
            this.maxParseSizeBytes = maxParseSizeBytes;
        }

        public Boolean getParseComments() {
            return parseComments;
        }

        public void setParseComments(Boolean parseComments) {
            this.parseComments = parseComments;
        }

        public Boolean getParseGit() {
            return parseGit;
        }

        public void setParseGit(Boolean parseGit) {
            this.parseGit = parseGit;
        }

        public Boolean getParseRobotsTxt() {
            return parseRobotsTxt;
        }

        public void setParseRobotsTxt(Boolean parseRobotsTxt) {
            this.parseRobotsTxt = parseRobotsTxt;
        }

        public Boolean getParseSitemapXml() {
            return parseSitemapXml;
        }

        public void setParseSitemapXml(Boolean parseSitemapXml) {
            this.parseSitemapXml = parseSitemapXml;
        }

        public Boolean getParseSVNEntries() {
            return parseSVNEntries;
        }

        public void setParseSVNEntries(Boolean parseSVNEntries) {
            this.parseSVNEntries = parseSVNEntries;
        }

        public Boolean getPostForm() {
            return postForm;
        }

        public void setPostForm(Boolean postForm) {
            this.postForm = postForm;
        }

        public Boolean getProcessForm() {
            return processForm;
        }

        public void setProcessForm(Boolean processForm) {
            this.processForm = processForm;
        }

        public Integer getRequestWaitTime() {
            return requestWaitTime;
        }

        public void setRequestWaitTime(Integer requestWaitTime) {
            this.requestWaitTime = requestWaitTime;
        }

        public Boolean getSendRefererHeader() {
            return sendRefererHeader;
        }

        public void setSendRefererHeader(Boolean sendRefererHeader) {
            this.sendRefererHeader = sendRefererHeader;
        }

        public Integer getThreadCount() {
            return threadCount;
        }

        public void setThreadCount(Integer threadCount) {
            this.threadCount = threadCount;
        }

        public String getUserAgent() {
            return userAgent;
        }

        public void setUserAgent(String userAgent) {
            this.userAgent = userAgent;
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
