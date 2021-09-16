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
package org.zaproxy.addon.automation.tests;

import org.zaproxy.addon.automation.AutomationData;

public abstract class TestData extends AutomationData {

    private AbstractAutomationTest test;
    private AbstractAutomationTest.OnFail onFail;

    public TestData(AbstractAutomationTest test) {
        this.test = test;
    }

    @Override
    public boolean isDefaultValue(String name) {
        if ("name".equals(name)) {
            return name.equals(getType());
        }
        return super.isDefaultValue(name);
    }

    public void setType(String type) {
        // Ignore, but method needed for reflection
    }

    public String getType() {
        return this.test.getTestType();
    }

    public String getName() {
        return this.test.getName();
    }

    public void setName(String name) {
        this.test.setName(name);
    }

    public AbstractAutomationTest.OnFail getOnFail() {
        return onFail;
    }

    public void setOnFail(AbstractAutomationTest.OnFail onFail) {
        this.onFail = onFail;
    }
}
