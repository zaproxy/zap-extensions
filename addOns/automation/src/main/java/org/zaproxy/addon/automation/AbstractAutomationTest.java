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
package org.zaproxy.addon.automation;

import java.util.LinkedHashMap;
import org.apache.commons.lang3.EnumUtils;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.Constant;

public abstract class AbstractAutomationTest {

    public enum OnFail {
        WARN,
        ERROR,
        INFO;

        @Override
        public String toString() {
            switch (this) {
                case ERROR:
                    return Constant.messages.getString("automation.dialog.test.onfail.error");
                case INFO:
                    return Constant.messages.getString("automation.dialog.test.onfail.info");
                case WARN:
                    return Constant.messages.getString("automation.dialog.test.onfail.warn");
                default:
                    return null;
            }
        }

        public static OnFail i18nToOnFail(String str) {
            for (OnFail o : OnFail.values()) {
                if (o.toString().equals(str)) {
                    return o;
                }
            }
            return null;
        }
    }

    private LinkedHashMap<?, ?> testData;
    private final AutomationJob job;
    private Boolean passed;
    private String name;

    public AbstractAutomationTest(LinkedHashMap<?, ?> testData, AutomationJob job) {
        this.testData = testData;
        this.job = job;
        String onFailStr = AutomationJob.safeCast(testData.get("onFail"), String.class);

        if (!EnumUtils.isValidEnumIgnoreCase(OnFail.class, onFailStr)) {
            throw new IllegalArgumentException(
                    Constant.messages.getString(
                            "automation.tests.invalidOnFail", getJobType(), onFailStr));
        }
    }

    public AbstractAutomationTest(String name, String onFail, AutomationJob job) {
        this.job = job;
        this.name = name;
        if (!EnumUtils.isValidEnumIgnoreCase(OnFail.class, onFail)) {
            throw new IllegalArgumentException(
                    Constant.messages.getString("automation.tests.invalidOnFail", name, onFail));
        }
    }

    public void logToProgress(AutomationProgress progress) throws RuntimeException {
        this.passed = runTest(progress);
        if (passed) {
            progress.info(getTestPassedMessage());
            return;
        }
        switch (getData().getOnFail()) {
            case WARN:
                progress.warn(getTestFailedMessage());
                break;
            case ERROR:
                progress.error(getTestFailedMessage());
                break;
            case INFO:
                progress.info(getTestFailedMessage());
                break;
            default:
                throw new RuntimeException("Unexpected onFail value " + getData().getOnFail());
        }
    }

    public final AutomationJob getJob() {
        return this.job;
    }

    public final String getJobType() {
        return this.job.getType();
    }

    public boolean hasPassed() {
        return this.passed == null ? false : this.passed;
    }

    public boolean hasRun() {
        return this.passed != null;
    }

    public void reset() {
        this.passed = null;
    }

    public LinkedHashMap<?, ?> getTestData() {
        return testData;
    }

    public void showDialog() {}

    public TestData getData() {
        return null;
    }

    public String getName() {
        if (!StringUtils.isEmpty(this.name)) {
            return this.name;
        }
        return this.getJob().getName() + "/" + this.getTestType();
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getSummary() {
        return "";
    };

    public abstract String getTestType();

    public abstract boolean runTest(AutomationProgress progress);

    public abstract String getTestPassedMessage();

    public abstract String getTestFailedMessage();
}
