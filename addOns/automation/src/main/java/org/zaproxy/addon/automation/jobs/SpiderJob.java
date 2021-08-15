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

import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.apache.commons.httpclient.URI;
import org.apache.commons.lang.StringUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.ConnectionParam;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.addon.automation.AbstractAutomationTest;
import org.zaproxy.addon.automation.AutomationData;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.AutomationStatisticTest;
import org.zaproxy.addon.automation.ContextWrapper;
import org.zaproxy.addon.automation.gui.SpiderJobDialog;
import org.zaproxy.zap.extension.spider.ExtensionSpider;
import org.zaproxy.zap.extension.spider.SpiderScan;
import org.zaproxy.zap.model.Target;
import org.zaproxy.zap.utils.Stats;
import org.zaproxy.zap.utils.ThreadUtils;

public class SpiderJob extends AutomationJob {

    public static final String JOB_NAME = "spider";
    private static final String OPTIONS_METHOD_NAME = "getSpiderParam";

    private static final String PARAM_CONTEXT = "context";
    private static final String PARAM_URL = "url";
    private static final String PARAM_FAIL_IF_LESS_URLS = "failIfFoundUrlsLessThan";
    private static final String PARAM_WARN_IF_LESS_URLS = "warnIfFoundUrlsLessThan";

    private ExtensionSpider extSpider;

    private Data data;
    private Parameters parameters = new Parameters();

    private UrlRequester urlRequester = new UrlRequester(this.getName());

    public SpiderJob() {
        this.data = new Data(this, parameters);
    }

    private ExtensionSpider getExtSpider() {
        if (extSpider == null) {
            extSpider =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionSpider.class);
        }
        return extSpider;
    }

    @Override
    public void verifyParameters(AutomationProgress progress) {
        LinkedHashMap<?, ?> jobData = this.getJobData();
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
                            "automation.spider.urls.added"));
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
    public void runJob(AutomationEnvironment env, AutomationProgress progress) {

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

        // Request all specified URLs
        for (String u : context.getUrls()) {
            urlStr = env.replaceVars(u);
            progress.info(
                    Constant.messages.getString("automation.info.requrl", this.getName(), urlStr));
            this.urlRequester.requestUrl(urlStr, progress);
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

        int scanId = this.getExtSpider().startScan(target, null, contextSpecificObjects.toArray());

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

        while (true) {
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                // Ignore
            }
            scan = this.getExtSpider().getScan(scanId);
            if (scan.isStopped()) {
                break;
            }
            if (System.currentTimeMillis() > endTime) {
                // It should have stopped but didn't (happens occasionally)
                this.getExtSpider().stopScan(scanId);
                break;
            }
        }

        int numUrlsFound = scan.getNumberOfURIsFound();
        progress.info(
                Constant.messages.getString(
                        "automation.info.urlsfound", this.getName(), numUrlsFound));
        Stats.incCounter("automation.spider.urls.added", numUrlsFound);
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
                "automation.dialog.spider.summary",
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
                        "automation.spider.urls.added",
                        Constant.messages.getString(
                                "automation.dialog.spider.tests.stats.defaultname", 100),
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

        public void requestUrl(String url, AutomationProgress progress) {
            // Request the URL
            try {
                final HttpMessage msg = new HttpMessage(new URI(url, true));
                httpSender.sendAndReceive(msg, true);

                if (msg.getResponseHeader().getStatusCode() != HttpStatusCode.OK) {
                    progress.error(
                            Constant.messages.getString(
                                    "automation.error.spider.url.notok",
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
                                    "automation.error.spider.url.badhost.proxychain",
                                    requester,
                                    url,
                                    e1.getMessage()));
                } else {
                    progress.error(
                            Constant.messages.getString(
                                    "automation.error.spider.url.badhost",
                                    requester,
                                    url,
                                    e1.getMessage()));
                }
            } catch (Exception e1) {
                progress.error(
                        Constant.messages.getString(
                                "automation.error.spider.url.failed",
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
