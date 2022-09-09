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
package org.zaproxy.addon.automation.gui;

import java.util.ArrayList;
import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.automation.AutomationEventPublisher;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.jobs.ActiveScanJob;
import org.zaproxy.addon.automation.jobs.PassiveScanWaitJob;
import org.zaproxy.addon.automation.tests.AbstractAutomationTest;
import org.zaproxy.addon.automation.tests.AutomationAlertTest;
import org.zaproxy.addon.automation.tests.AutomationMonitorTest;
import org.zaproxy.addon.automation.tests.AutomationStatisticTest;
import org.zaproxy.addon.automation.tests.UrlPresenceTest;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class AddTestDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String TITLE = "automation.dialog.addtest.title";
    private static final String TEST_PARAM = "automation.dialog.addtest.test";
    private static final String ALERT_TEST_NAME = "automation.dialog.test.alert.name";
    private static final String MONITOR_TEST_NAME = "automation.dialog.test.monitor.name";
    private static final String STATS_TEST_NAME = "automation.dialog.test.statistic.name";
    private static final String URL_PRESENCE_TEST_NAME = "automation.dialog.test.urlpresence.name";

    private AutomationJob job;

    public AddTestDialog(AutomationJob job) {
        super(View.getSingleton().getMainFrame(), TITLE, DisplayUtils.getScaledDimension(300, 200));
        this.job = job;

        List<String> testNames = new ArrayList<>();
        testNames.add(Constant.messages.getString(STATS_TEST_NAME));
        if (job.supportsMonitorTests()) {
            testNames.add(Constant.messages.getString(MONITOR_TEST_NAME));
        }
        testNames.add(Constant.messages.getString(URL_PRESENCE_TEST_NAME));

        if (job instanceof PassiveScanWaitJob || job instanceof ActiveScanJob) {
            testNames.add(Constant.messages.getString(ALERT_TEST_NAME));
        }

        this.addComboField(TEST_PARAM, testNames, "");
        this.addPadding();
    }

    @Override
    public void save() {
        String testName = this.getStringValue(TEST_PARAM);
        AbstractAutomationTest test;
        if (testName.equals(Constant.messages.getString(STATS_TEST_NAME))) {
            test = new AutomationStatisticTest(job, job.getPlan().getProgress());
        } else if (testName.equals(Constant.messages.getString(MONITOR_TEST_NAME))) {
            test = new AutomationMonitorTest(job, job.getPlan().getProgress());
        } else if (testName.equals(Constant.messages.getString(URL_PRESENCE_TEST_NAME))) {
            test = new UrlPresenceTest(job, job.getPlan().getProgress());
        } else {
            test = new AutomationAlertTest(job, job.getPlan().getProgress());
        }
        job.addTest(test);
        AutomationEventPublisher.publishEvent(AutomationEventPublisher.TEST_ADDED, job, null);

        test.showDialog();
    }

    @Override
    public String validateFields() {
        // Nothing to do
        return null;
    }
}
