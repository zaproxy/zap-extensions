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
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.extension.spiderAjax.AjaxSpiderTarget;
import org.zaproxy.zap.extension.spiderAjax.ExtensionAjax;
import org.zaproxy.zap.extension.spiderAjax.SpiderListener;
import org.zaproxy.zap.extension.spiderAjax.SpiderThread;
import org.zaproxy.zap.model.Context;

public class AjaxSpiderJob extends AutomationJob {

    private static final String JOB_NAME = "spiderAjax";
    private static final String OPTIONS_METHOD_NAME = "getAjaxSpiderParam";

    private static final String PARAM_CONTEXT = "context";
    private static final String PARAM_URL = "url";
    private static final String PARAM_FAIL_IF_LESS_URLS = "failIfFoundUrlsLessThan";
    private static final String PARAM_WARN_IF_LESS_URLS = "warnIfFoundUrlsLessThan";
    private static final String PARAM_MAX_DURATION = "maxDuration";

    private ExtensionAjax extSpider;

    private int failIfFoundUrlsLessThan = 0;
    private int warnIfFoundUrlsLessThan = 0;

    // Local copy
    private int maxDuration = 0;

    private String contextName;
    private String url;

    private boolean inScopeOnly = true;

    public AjaxSpiderJob() {}

    private ExtensionAjax getExtSpider() {
        if (extSpider == null) {
            extSpider =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionAjax.class);
        }
        return extSpider;
    }

    public boolean applyCustomParameter(String name, String value) {
        switch (name) {
            case PARAM_CONTEXT:
                contextName = value;
                return true;
            case PARAM_URL:
                url = value;
                return true;
            case PARAM_FAIL_IF_LESS_URLS:
                failIfFoundUrlsLessThan = Integer.parseInt(value);
                return true;
            case PARAM_WARN_IF_LESS_URLS:
                warnIfFoundUrlsLessThan = Integer.parseInt(value);
                return true;
            case PARAM_MAX_DURATION:
                maxDuration = Integer.parseInt(value);
                // Don't consume this as we still want it to be applied to the spider params
                return false;
            default:
                // Ignore
                break;
        }
        return false;
    }

    @Override
    public Map<String, String> getCustomConfigParameters() {
        Map<String, String> map = super.getCustomConfigParameters();
        map.put(PARAM_CONTEXT, "");
        map.put(PARAM_URL, "");
        map.put(PARAM_FAIL_IF_LESS_URLS, "0");
        map.put(PARAM_WARN_IF_LESS_URLS, "0");
        return map;
    }

    @Override
    public void runJob(
            AutomationEnvironment env, LinkedHashMap<?, ?> jobData, AutomationProgress progress) {

        Context context;
        if (contextName != null) {
            context = env.getContext(contextName);
            if (context == null) {
                progress.error(
                        Constant.messages.getString(
                                "automation.error.context.unknown",
                                env.getUrlStringForContext(context)));
                return;
            }
        } else {
            context = env.getDefaultContext();
        }

        URI uri = null;
        try {
            if (url != null) {
                uri = new URI(url);
            } else {
                uri = new URI(env.getUrlStringForContext(context).toString());
            }
        } catch (Exception e1) {
            progress.error(
                    Constant.messages.getString(
                            "automation.error.context.badurl",
                            env.getUrlStringForContext(context)));
            return;
        }

        AjaxSpiderTarget.Builder targetBuilder =
                AjaxSpiderTarget.newBuilder(Model.getSingleton().getSession())
                        .setContext(context)
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
        if (maxDuration > 0) {
            // The spider should stop, if it doesnt we will stop it (after a few seconds leeway)
            endTime =
                    System.currentTimeMillis()
                            + TimeUnit.MINUTES.toMillis(maxDuration)
                            + TimeUnit.SECONDS.toMillis(5);
        }

        // Wait for the ajax spider to finish

        while (true) {
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                // Ignore
            }
            if (!spiderThread.isRunning()) {
                break;
            }
            if (System.currentTimeMillis() > endTime) {
                // It should have stopped but didn't (happens occasionally)
                spiderThread.stopSpider();
                break;
            }
        }
        int numUrlsFound = listener.getMessagesFound();
        progress.info(
                Constant.messages.getString(
                        "automation.info.urlsfound", this.getType(), numUrlsFound));
        if (numUrlsFound < this.failIfFoundUrlsLessThan) {
            progress.error(
                    Constant.messages.getString(
                            "automation.error.urlsfound",
                            this.getType(),
                            numUrlsFound,
                            this.failIfFoundUrlsLessThan));
        }
        if (numUrlsFound < this.warnIfFoundUrlsLessThan) {
            progress.warn(
                    Constant.messages.getString(
                            "automation.error.urlsfound",
                            this.getType(),
                            numUrlsFound,
                            this.failIfFoundUrlsLessThan));
        }
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

    public int getFailIfFoundUrlsLessThan() {
        return failIfFoundUrlsLessThan;
    }

    public int getWarnIfFoundUrlsLessThan() {
        return warnIfFoundUrlsLessThan;
    }

    public int getMaxDuration() {
        return maxDuration;
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

    public String getTemplateDataMin() {
        return ExtensionAjaxAutomation.getResourceAsString(this.getType() + "-min.yaml");
    }

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
}
