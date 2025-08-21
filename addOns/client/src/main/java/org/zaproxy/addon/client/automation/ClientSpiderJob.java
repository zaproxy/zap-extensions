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
package org.zaproxy.addon.client.automation;

import java.util.Map;
import java.util.concurrent.TimeUnit;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.configuration.XMLConfiguration;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.addon.automation.AutomationData;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.ContextWrapper;
import org.zaproxy.addon.automation.jobs.JobData;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.addon.client.ClientOptions;
import org.zaproxy.addon.client.ClientOptions.ScopeCheck;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.client.spider.ClientSpider;
import org.zaproxy.addon.commonlib.Constants;
import org.zaproxy.zap.users.User;

public class ClientSpiderJob extends AutomationJob {

    private static final Logger LOGGER = LogManager.getLogger(ClientSpiderJob.class);

    private static final String JOB_NAME = "spiderClient";

    private ExtensionClientIntegration extSpider;

    private Data data;
    private Parameters parameters = new Parameters();
    private boolean forceStop;

    public ClientSpiderJob() {
        this.data = new Data(this, parameters);
    }

    private ExtensionClientIntegration getExtClient() {
        if (extSpider == null) {
            extSpider =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionClientIntegration.class);
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
                parametersData, this.parameters, this.getName(), new String[] {}, progress);
    }

    @Override
    public void applyParameters(AutomationProgress progress) {
        // Nothing to do
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

        forceStop = false;
        int scanId = -1;
        try {
            scanId =
                    getExtClient()
                            .startScan(
                                    uriStr, paramsToOptions(), context.getContext(), user, false);
        } catch (URIException e) {
            progress.error(Constant.messages.getString("automation.error.context.badurl", uriStr));
            return;
        } catch (Exception e) {
            progress.error(
                    Constant.messages.getString(
                            "automation.error.unexpected.internal", e.getMessage()));
            LOGGER.error(e.getMessage(), e);
            return;
        }
        ClientSpider spider = getExtClient().getScan(scanId);

        long endTime = Long.MAX_VALUE;
        if (JobUtils.unBox(this.getParameters().getMaxDuration()) > 0) {
            // The spider should stop, if it doesnt we will stop it (after a few seconds leeway)
            endTime =
                    System.currentTimeMillis()
                            + TimeUnit.MINUTES.toMillis(this.getParameters().getMaxDuration())
                            + TimeUnit.SECONDS.toMillis(5);
        }

        // Wait for the client spider to finish

        while (true) {
            this.sleep(500);

            if (!spider.isRunning() || forceStop) {
                break;
            }
            if (!this.runMonitorTests(progress) || System.currentTimeMillis() > endTime) {
                forceStop = true;
                break;
            }
        }
        if (forceStop) {
            spider.stopScan();
            progress.info(Constant.messages.getString("automation.info.jobstopped", getType()));
        }
    }

    @Override
    public void stop() {
        forceStop = true;
    }

    protected ClientOptions paramsToOptions() {
        ClientOptions options = new ClientOptions();
        options.load(new XMLConfiguration());

        if (!StringUtils.isBlank(this.parameters.getBrowserId())) {
            options.setBrowserId(this.parameters.getBrowserId());
        }
        if (this.parameters.getMaxDuration() != null) {
            options.setMaxDuration(this.parameters.getMaxDuration());
        }
        if (this.parameters.getMaxChildren() != null) {
            options.setMaxChildren(this.parameters.getMaxChildren());
        }
        if (this.parameters.getMaxCrawlDepth() != null) {
            options.setMaxDepth(this.parameters.getMaxCrawlDepth());
        }
        if (this.parameters.getNumberOfBrowsers() != null) {
            options.setThreadCount(this.parameters.getNumberOfBrowsers());
        }
        if (this.parameters.getInitialLoadTime() != null) {
            options.setInitialLoadTimeInSecs(this.parameters.getInitialLoadTime());
        }
        if (this.parameters.getPageLoadTime() != null) {
            options.setPageLoadTimeInSecs(this.parameters.getPageLoadTime());
        }
        if (this.parameters.getShutdownTime() != null) {
            options.setShutdownTimeInSecs(this.parameters.getShutdownTime());
        }
        return options;
    }

    private ContextWrapper getContextWrapper(
            AutomationEnvironment env, AutomationProgress progress) {
        String contextName = this.getParameters().getContext();
        if (StringUtils.isEmpty(contextName)) {
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
    public String getTemplateDataMin() {
        return ExtensionClientAutomation.getResourceAsString(this.getType() + "-min.yaml");
    }

    @Override
    public String getTemplateDataMax() {
        return ExtensionClientAutomation.getResourceAsString(this.getType() + "-max.yaml");
    }

    @Override
    public Order getOrder() {
        return Order.LAST_EXPLORE;
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
    public String getType() {
        return JOB_NAME;
    }

    @Override
    public void showDialog() {
        new ClientSpiderJobDialog(this).setVisible(true);
    }

    @Override
    public String getSummary() {
        String context = this.getParameters().getContext();
        if (StringUtils.isEmpty(context)) {
            context = Constant.messages.getString("client.automation.default");
        }
        return Constant.messages.getString(
                "client.automation.dialog.summary",
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

    @Getter
    @Setter
    public static class Parameters extends AutomationData {
        private String context = "";
        private String user = "";
        private String url = "";
        private Integer maxDuration;
        private Integer maxChildren;
        private Integer maxCrawlDepth = ClientOptions.DEFAULT_MAX_DEPTH;
        private Integer numberOfBrowsers = Constants.getDefaultThreadCount() / 2;
        private String browserId;
        private Integer initialLoadTime = ClientOptions.DEFAULT_INITIAL_LOAD_TIME;
        private Integer pageLoadTime = ClientOptions.DEFAULT_PAGE_LOAD_TIME;
        private Integer shutdownTime = ClientOptions.DEFAULT_SHUTDOWN_TIME;
        private String scopeCheck = ScopeCheck.getDefault().toString();

        public Parameters() {}
    }
}
