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

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import org.apache.commons.lang.StringUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.gui.StatisticTestDialog;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.zap.extension.stats.ExtensionStats;
import org.zaproxy.zap.extension.stats.InMemoryStats;

public class AutomationStatisticTest extends AbstractAutomationTest {

    public static final String TEST_TYPE = "stats";

    private long stat;
    private Data data;

    public enum Operator {
        LESS("<"),
        GREATER(">"),
        LESS_OR_EQUAL("<="),
        GREATER_OR_EQUAL(">="),
        EQUAL("=="),
        NOT_EQUAL("!=");

        private final String symbol;

        Operator(String symbol) {
            this.symbol = symbol;
        }

        public String getSymbol() {
            return symbol;
        }
    }

    public AutomationStatisticTest(
            Map<?, ?> testData, AutomationJob job, AutomationProgress progress) {
        super(testData, job);
        data = new Data(this);
        JobUtils.applyParamsToObject(testData, this.getData(), this.getName(), null, progress);

        if (this.getData().getOnFail() == null) {
            progress.error(
                    Constant.messages.getString(
                            "automation.tests.error.badonfail", getJobType(), this.getName()));
        }
        String operator = this.getData().getOperator();
        if (StringUtils.isEmpty(operator)) {
            progress.error(
                    Constant.messages.getString(
                            "automation.tests.stats.error.nooperator",
                            getJobType(),
                            this.getName()));
        } else if (Arrays.stream(Operator.values())
                .map(Operator::getSymbol)
                .noneMatch(o -> o.equals(operator))) {
            progress.error(
                    Constant.messages.getString(
                            "automation.tests.stats.error.badoperator",
                            getJobType(),
                            this.getName(),
                            operator));
        }
        if (StringUtils.isEmpty(data.getStatistic())) {
            progress.error(
                    Constant.messages.getString(
                            "automation.tests.stats.error.nostatistic",
                            getJobType(),
                            this.getName()));
        }
        if (this.getData().getValue() == null) {
            progress.error(
                    Constant.messages.getString(
                            "automation.tests.stats.error.novalue", getJobType(), this.getName()));
        }
    }

    private static LinkedHashMap<?, ?> paramsToData(
            String key, String name, String site, String operator, long value, String onFail) {
        LinkedHashMap<String, Object> map = new LinkedHashMap<>();
        map.put("statistic", key);
        map.put("name", name);
        map.put("site", site);
        map.put("operator", operator);
        map.put("value", value);
        map.put("onFail", onFail);
        return map;
    }

    public AutomationStatisticTest(
            String key,
            String name,
            String operator,
            long value,
            String onFail,
            AutomationJob job,
            AutomationProgress progress)
            throws IllegalArgumentException {
        this(paramsToData(key, name, "", operator, value, onFail), job, progress);
    }

    public AutomationStatisticTest(
            String key,
            String name,
            String site,
            String operator,
            long value,
            String onFail,
            AutomationJob job,
            AutomationProgress progress)
            throws IllegalArgumentException {
        this(paramsToData(key, name, site, operator, value, onFail), job, progress);
    }

    public AutomationStatisticTest(AutomationJob job, AutomationProgress progress)
            throws IllegalArgumentException {
        super("", AbstractAutomationTest.OnFail.INFO.name(), job);
        data = new Data(this);
        data.setOnFail(AbstractAutomationTest.OnFail.INFO);
    }

    @Override
    public boolean runTest(AutomationProgress progress) throws RuntimeException {
        if (this.getData().getValue() == null) {
            progress.error(
                    Constant.messages.getString(
                            "automation.tests.stats.error.novalue", getJobType(), this.getName()));
            return false;
        }

        stat =
                getStatistic(
                        this.getData().getStatistic(),
                        this.getJob().getEnv().replaceVars(this.getData().getSite()));

        switch (getOperator(this.getData().getOperator())) {
            case LESS:
                return stat < this.getData().getValue();
            case GREATER:
                return stat > this.getData().getValue();
            case LESS_OR_EQUAL:
                return stat <= this.getData().getValue();
            case GREATER_OR_EQUAL:
                return stat >= this.getData().getValue();
            case EQUAL:
                return stat == this.getData().getValue();
            case NOT_EQUAL:
                return stat != this.getData().getValue();
            default:
                throw new RuntimeException("Unexpected operator " + this.getData().getOperator());
        }
    }

    private Operator getOperator(String opString) {
        return Arrays.stream(Operator.values())
                .filter(o -> o.getSymbol().equals(opString))
                .findFirst()
                .get();
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
        String testPassedReason =
                stat + " " + this.getData().getOperator() + " " + this.getData().getValue();
        return Constant.messages.getString(
                "automation.tests.pass",
                getJobType(),
                getTestType(),
                this.getName(),
                testPassedReason);
    }

    @Override
    public String getTestFailedMessage() {
        String testFailedReason =
                stat + " " + getInverseOperator().getSymbol() + " " + this.getData().getValue();
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
                "automation.tests.stats.summary",
                this.getData().getOnFail().toString(),
                this.getData().getStatistic(),
                this.getData().getOperator(),
                this.getData().getValue());
    }

    private Operator getInverseOperator() {
        switch (getOperator(this.getData().getOperator())) {
            case LESS:
                return Operator.GREATER_OR_EQUAL;
            case GREATER:
                return Operator.LESS_OR_EQUAL;
            case LESS_OR_EQUAL:
                return Operator.GREATER;
            case GREATER_OR_EQUAL:
                return Operator.LESS;
            case EQUAL:
                return Operator.NOT_EQUAL;
            case NOT_EQUAL:
                return Operator.EQUAL;
            default:
                throw new RuntimeException("Unexpected operator " + this.getData().getOperator());
        }
    }

    @Override
    public void showDialog() {
        new StatisticTestDialog(this).setVisible(true);
    }

    @Override
    public Data getData() {
        return data;
    }

    public static class Data extends TestData {

        private String statistic;
        private String site;
        private String operator;
        private Long value;

        public Data(AutomationStatisticTest test) {
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

        public String getOperator() {
            return operator;
        }

        public void setOperator(String operator) {
            this.operator = operator;
        }

        public Long getValue() {
            return value;
        }

        public void setValue(Long value) {
            this.value = value;
        }
    }
}
