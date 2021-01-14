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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.apache.commons.httpclient.URI;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.extension.spider.ExtensionSpider;
import org.zaproxy.zap.extension.spider.SpiderScan;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.Target;

public class SpiderJob extends AutomationJob {

    public static final String JOB_NAME = "spider";
    private static final String OPTIONS_METHOD_NAME = "getSpiderParam";

    private static final String PARAM_CONTEXT = "context";
    private static final String PARAM_URL = "url";
    private static final String PARAM_FAIL_IF_LESS_URLS = "failIfFoundUrlsLessThan";
    private static final String PARAM_WARN_IF_LESS_URLS = "warnIfFoundUrlsLessThan";
    private static final String PARAM_MAX_DURATION = "maxDuration";

    private ExtensionSpider extSpider;

    private int failIfFoundUrlsLessThan = 0;
    private int warnIfFoundUrlsLessThan = 0;

    // Local copy
    private int maxDuration = 0;

    private String contextName;
    private String url;

    public SpiderJob() {}

    private ExtensionSpider getExtSpider() {
        if (extSpider == null) {
            extSpider =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionSpider.class);
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
                uri = new URI(url, true);
            } else {
                uri = new URI(env.getUrlStringForContext(context).toString(), true);
            }
        } catch (Exception e1) {
            progress.error(
                    Constant.messages.getString(
                            "automation.error.context.badurl",
                            env.getUrlStringForContext(context)));
            return;
        }

        Target target = new Target(context);
        target.setRecurse(true);
        List<Object> contextSpecificObjects = new ArrayList<>();
        contextSpecificObjects.add(uri);

        int scanId = this.getExtSpider().startScan(target, null, contextSpecificObjects.toArray());

        long endTime = Long.MAX_VALUE;
        if (maxDuration > 0) {
            // The spider should stop, if it doesnt we will stop it (after a few seconds leeway
            endTime =
                    System.currentTimeMillis()
                            + TimeUnit.MINUTES.toMillis(maxDuration)
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
            case "confirmRemoveDomainAlwaysInScope":
            case "maxScansInUI":
            case "showAdvancedDialog":
            case "skipURLString":
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
}
