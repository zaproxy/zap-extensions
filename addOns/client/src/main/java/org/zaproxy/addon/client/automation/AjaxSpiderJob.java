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
package org.zaproxy.addon.client.automation;

import java.util.Map;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.jobs.JobUtils;

/**
 * Stands in for the {@code spiderAjax} automation job when the AJAX Spider add-on is not installed,
 * running the Client Spider instead so that existing plans keep working.
 */
public class AjaxSpiderJob extends ClientSpiderJob {

    private static final String JOB_NAME = "spiderAjax";

    /**
     * Parameters supported by the real AJAX Spider job that have no Client Spider equivalent, so
     * are silently ignored rather than reported as unrecognised.
     */
    private static final String[] IGNORED_PARAMS = {
        "clickDefaultElems",
        "clickElemsOnce",
        "elements",
        "enableExtensions",
        "eventWait",
        "excludedElements",
        "failIfFoundUrlsLessThan",
        "inScopeOnly",
        "maxCrawlStates",
        "randomInputs",
        "reloadWait",
        "warnIfFoundUrlsLessThan",
    };

    public AjaxSpiderJob() {
        super();
    }

    @Override
    public String getType() {
        return JOB_NAME;
    }

    @Override
    public void verifyParameters(AutomationProgress progress) {
        progress.warn(Constant.messages.getString("client.automation.ajaxSpiderJob.warn"));

        Map<?, ?> jobData = this.getJobData();
        if (jobData == null) {
            return;
        }
        Map<?, ?> parametersData = (Map<?, ?>) jobData.get("parameters");
        JobUtils.applyParamsToObject(
                parametersData, this.getParameters(), this.getName(), IGNORED_PARAMS, progress);
    }
}
