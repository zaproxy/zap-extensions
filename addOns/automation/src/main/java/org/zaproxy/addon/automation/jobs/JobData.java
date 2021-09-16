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

import java.util.List;
import java.util.stream.Collectors;
import org.zaproxy.addon.automation.AutomationData;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.tests.AbstractAutomationTest;

public abstract class JobData extends AutomationData {

    private AutomationJob job;

    public JobData(AutomationJob job) {
        super();
        this.job = job;
    }

    @Override
    public boolean isDefaultValue(String name) {
        if ("name".equals(name)) {
            return name.equals(getType());
        }
        return super.isDefaultValue(name);
    }

    public String getType() {
        return this.job.getType();
    }

    public String getName() {
        return this.job.getName();
    }

    public void setName(String name) {
        this.job.setName(name);
    }

    public List<AutomationData> getTests() {
        List<AbstractAutomationTest> tests = this.job.getTests();
        if (tests.isEmpty()) {
            // So that no test element included in the YAML
            return null;
        }
        return tests.stream().map(t -> t.getData()).collect(Collectors.toList());
    }
}
