/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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

import java.util.LinkedHashMap;
import java.util.Map;
import org.apache.commons.lang.StringUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.gui.MonitorTestDialog;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.zap.extension.stats.ExtensionStats;
import org.zaproxy.zap.extension.stats.InMemoryStats;

public class AutomationMonitorTest extends AbstractAutomationTest {

    public static final String TEST_TYPE = "monitor";

    private long stat;
    private Data data;

    public AutomationMonitorTest(
            Map<?, ?> testData, AutomationJob job, AutomationProgress progress) {
        super(testData, job);
        data = new Data(this);
        JobUtils.applyParamsToObject(testData, this.getData(), this.getName(), null, progress);

        if (this.getData().getOnFail() == null) {
            progress.error(
                    Constant.messages.getString(
                            "automation.tests.error.badonfail", getJobType(), this.getName()));
        }
        if (StringUtils.isEmpty(data.getStatistic())) {
            progress.error(
                    Constant.messages.getString(
                            "automation.tests.monitor.error.nostatistic",
                            getJobType(),
                            this.getName()));
        }
        if (this.getData().getThreshold() == null) {
            progress.error(
                    Constant.messages.getString(
                            "automation.tests.monitor.error.nothreshold",
                            getJobType(),
                            this.getName()));
        }
    }

    private static LinkedHashMap<?, ?> paramsToData(
            String key, String name, String site, long threshold, String onFail) {
        LinkedHashMap<String, Object> map = new LinkedHashMap<>();
        map.put("statistic", key);
        map.put("name", name);
        map.put("site", site);
        map.put("threshold", threshold);
        map.put("onFail", onFail);
        return map;
    }

    public AutomationMonitorTest(
            String key,
            String name,
            long threshold,
            String onFail,
            AutomationJob job,
            AutomationProgress progress)
            throws IllegalArgumentException {
        this(paramsToData(key, name, "", threshold, onFail), job, progress);
    }

    public AutomationMonitorTest(
            String key,
            String name,
            String site,
            long threshold,
            String onFail,
            AutomationJob job,
            AutomationProgress progress)
            throws IllegalArgumentException {
        this(paramsToData(key, name, site, threshold, onFail), job, progress);
    }

    public AutomationMonitorTest(AutomationJob job, AutomationProgress progress)
            throws IllegalArgumentException {
        super("", AbstractAutomationTest.OnFail.INFO.name(), job);
        data = new Data(this);
        data.setOnFail(AbstractAutomationTest.OnFail.INFO);
    }

    @Override
    public boolean runTest(AutomationProgress progress) throws RuntimeException {
        if (this.getData().getThreshold() == null) {
            progress.error(
                    Constant.messages.getString(
                            "automation.tests.monitor.error.nothreshold",
                            getJobType(),
                            this.getName()));
            return false;
        }

        stat =
                getStatistic(
                        this.getData().getStatistic(),
                        this.getJob().getEnv().replaceVars(this.getData().getSite()));

        return stat < this.getData().getThreshold();
    }

    private long getStatistic(String stat, String site) {
        InMemoryStats inMemoryStats =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionStats.class)
                        .getInMemoryStats();

        if (inMemoryStats == null) {
            return 0;
        }
        if (StringUtils.isEmpty(site)) {
            return JobUtils.unBox(inMemoryStats.getStat(stat));
        }
        return JobUtils.unBox(inMemoryStats.getStat(site, stat));
    }

    @Override
    public String getTestType() {
        return TEST_TYPE;
    }

    @Override
    public String getTestPassedMessage() {
        String testPassedReason = stat + " " + this.getData().getThreshold();
        return Constant.messages.getString(
                "automation.tests.pass",
                getJobType(),
                getTestType(),
                this.getName(),
                testPassedReason);
    }

    @Override
    public String getTestFailedMessage() {
        String testFailedReason = stat + " > " + this.getData().getThreshold();
        return Constant.messages.getString(
                "automation.tests.fail",
                getJobType(),
                getTestType(),
                this.getName(),
                testFailedReason);
    }

    @Override
    public String getSummary() {
        return Constant.messages.getString(
                "automation.tests.monitor.summary",
                this.getData().getOnFail().toString(),
                this.getData().getStatistic(),
                this.getData().getThreshold());
    }

    @Override
    public void showDialog() {
        new MonitorTestDialog(this).setVisible(true);
    }

    @Override
    public Data getData() {
        return data;
    }

    public static class Data extends TestData {

        private String statistic;
        private String site;
        private Long threshold;

        public Data(AutomationMonitorTest test) {
            super(test);
        }

        public String getStatistic() {
            return statistic;
        }

        public void setStatistic(String key) {
            this.statistic = key;
        }

        public String getSite() {
            return site;
        }

        public void setSite(String site) {
            this.site = site;
        }

        public Long getThreshold() {
            return threshold;
        }

        public void setThreshold(Long threshold) {
            this.threshold = threshold;
        }
    }
}
