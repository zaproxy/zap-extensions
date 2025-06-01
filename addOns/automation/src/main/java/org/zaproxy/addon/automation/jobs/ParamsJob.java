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

import java.util.Collections;
import java.util.List;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.JobResultData;

public class ParamsJob extends AutomationJob {

    public static final String JOB_NAME = "params";

    public ParamsJob() {}

    @Override
    public boolean isDataJob() {
        return true;
    }

    @Override
    public List<JobResultData> getJobResultData() {
        return Collections.singletonList(new ParamsJobResultData(this.getName()));
    }

    @Override
    public String getTemplateDataMin() {
        return "";
    }

    @Override
    public String getTemplateDataMax() {
        return "";
    }

    @Override
    public Order getOrder() {
        return Order.REPORT;
    }

    @Override
    public void runJob(AutomationEnvironment env, AutomationProgress progress) {}

    @Override
    public String getSummary() {
        return "";
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
}
