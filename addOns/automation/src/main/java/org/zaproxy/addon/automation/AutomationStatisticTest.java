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

import java.util.Arrays;
import java.util.LinkedHashMap;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.zap.extension.stats.ExtensionStats;
import org.zaproxy.zap.extension.stats.InMemoryStats;

public class AutomationStatisticTest extends AbstractAutomationTest {

    public static final String TEST_TYPE = "stats";

    public final String key;
    public final String name;
    public final Operator operator;
    public final long value;
    public final String onFail;
    private long stat;

    enum Operator {
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

    public AutomationStatisticTest(LinkedHashMap<?, ?> testData, String jobType) {
        super(testData, jobType);
        String statistic = AutomationJob.safeCast(testData.get("statistic"), String.class);
        String operator = AutomationJob.safeCast(testData.get("operator"), String.class);
        Number number = AutomationJob.safeCast(testData.get("value"), Number.class);
        String onFail = AutomationJob.safeCast(testData.get("onFail"), String.class);
        if (statistic == null || operator == null || number == null || onFail == null) {
            throw new IllegalArgumentException(
                    Constant.messages.getString(
                            "automation.tests.missingOrInvalidProperties",
                            getJobType(),
                            getTestType()));
        }
        value = number.longValue();
        String name = AutomationJob.safeCast(testData.get("name"), String.class);
        if (name == null || name.isEmpty()) {
            name = statistic + ' ' + operator + ' ' + value;
        }
        this.name = name;

        if (Arrays.stream(Operator.values())
                .map(Operator::getSymbol)
                .noneMatch(o -> o.equals(operator))) {
            throw new IllegalArgumentException(
                    Constant.messages.getString(
                            "automation.tests.stats.invalidOperator",
                            getJobType(),
                            name,
                            operator));
        }
        this.key = statistic;
        this.operator =
                Arrays.stream(Operator.values())
                        .filter(o -> o.getSymbol().equals(operator))
                        .findFirst()
                        .get();
        this.onFail = onFail;
    }

    private static LinkedHashMap<?, ?> paramsToData(
            String key, String name, String operator, long value, String onFail) {
        LinkedHashMap<String, Object> map = new LinkedHashMap<>();
        map.put("statistic", key);
        map.put("name", name);
        map.put("operator", operator);
        map.put("value", value);
        map.put("onFail", onFail);
        return map;
    }

    public AutomationStatisticTest(
            String key, String name, String operator, long value, String onFail, String jobType)
            throws IllegalArgumentException {
        this(paramsToData(key, name, operator, value, onFail), jobType);
    }

    @Override
    public boolean runTest(AutomationProgress progress) throws RuntimeException {
        InMemoryStats inMemoryStats =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionStats.class)
                        .getInMemoryStats();
        stat =
                inMemoryStats != null
                        ? inMemoryStats.getStat(key) != null ? inMemoryStats.getStat(key) : 0
                        : 0;
        switch (operator) {
            case LESS:
                return stat < value;
            case GREATER:
                return stat > value;
            case LESS_OR_EQUAL:
                return stat <= value;
            case GREATER_OR_EQUAL:
                return stat >= value;
            case EQUAL:
                return stat == value;
            case NOT_EQUAL:
                return stat != value;
            default:
                throw new RuntimeException("Unexpected operator " + operator);
        }
    }

    @Override
    public String getName() {
        return this.name;
    }

    @Override
    public String getTestType() {
        return TEST_TYPE;
    }

    @Override
    public String getTestPassedMessage() {
        String testPassedReason = stat + " " + operator.getSymbol() + " " + value;
        return Constant.messages.getString(
                "automation.tests.pass", getJobType(), getTestType(), name, testPassedReason);
    }

    @Override
    public String getTestFailedMessage() {
        String testFailedReason = stat + " " + getInverseOperator().getSymbol() + " " + value;
        return Constant.messages.getString(
                "automation.tests.fail", getJobType(), getTestType(), name, testFailedReason);
    }

    private Operator getInverseOperator() {
        switch (operator) {
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
                throw new RuntimeException("Unexpected operator " + operator);
        }
    }
}
