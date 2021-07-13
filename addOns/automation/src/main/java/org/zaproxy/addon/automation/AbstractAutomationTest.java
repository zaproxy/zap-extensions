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
import org.parosproxy.paros.Constant;

public abstract class AbstractAutomationTest {

    enum OnFail {
        WARN,
        ERROR,
        INFO
    }

    private LinkedHashMap<?, ?> testData;
    private final OnFail onFail;
    private final String jobType;
    private Boolean passed;

    public AbstractAutomationTest(LinkedHashMap<?, ?> testData, String jobType) {
        this.testData = testData;
        String onFailStr = AutomationJob.safeCast(testData.get("onFail"), String.class);

        if (!EnumUtils.isValidEnumIgnoreCase(OnFail.class, onFailStr)) {
            throw new IllegalArgumentException(
                    Constant.messages.getString(
                            "automation.tests.invalidOnFail", getJobType(), onFailStr));
        }
        this.onFail = EnumUtils.getEnumIgnoreCase(OnFail.class, onFailStr);
        this.jobType = jobType;
    }

    public AbstractAutomationTest(String name, String onFail, String jobType) {
        if (!EnumUtils.isValidEnumIgnoreCase(OnFail.class, onFail)) {
            throw new IllegalArgumentException(
                    Constant.messages.getString("automation.tests.invalidOnFail", name, onFail));
        }
        this.onFail = EnumUtils.getEnumIgnoreCase(OnFail.class, onFail);
        this.jobType = jobType;
    }

    public void logToProgress(AutomationProgress progress) throws RuntimeException {
        this.passed = runTest(progress);
        if (passed) {
            progress.info(getTestPassedMessage());
            return;
        }
        switch (onFail) {
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
                throw new RuntimeException("Unexpected onFail value " + onFail);
        }
    }

    public final String getJobType() {
        return this.jobType;
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

    public abstract String getName();

    public abstract String getTestType();

    public abstract boolean runTest(AutomationProgress progress);

    public abstract String getTestPassedMessage();

    public abstract String getTestFailedMessage();
}
