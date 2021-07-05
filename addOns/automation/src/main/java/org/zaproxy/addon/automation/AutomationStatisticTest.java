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
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.zap.extension.stats.ExtensionStats;
import org.zaproxy.zap.extension.stats.InMemoryStats;

public class AutomationStatisticTest extends AbstractAutomationTest {
    public final String key;
    public final String name;
    public final Operator operator;
    public final long value;
    public final String onFail;
    public final String jobType;
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

    public AutomationStatisticTest(
            String key, String name, String operator, long value, String onFail, String jobType)
            throws IllegalArgumentException {
        super(name, onFail);
        if (Arrays.stream(Operator.values())
                .map(Operator::getSymbol)
                .noneMatch(o -> o.equals(operator))) {
            throw new IllegalArgumentException(
                    Constant.messages.getString(
                            "automation.tests.stats.invalidOperator", jobType, name, operator));
        }
        this.key = key;
        this.name = name;
        this.operator =
                Arrays.stream(Operator.values())
                        .filter(o -> o.getSymbol().equals(operator))
                        .findFirst()
                        .get();
        this.value = value;
        this.onFail = onFail;
        this.jobType = jobType;
    }

    @Override
    public boolean hasPassed() throws RuntimeException {
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
    protected String getTestPassedMessage() {
        String testPassedReason = stat + " " + operator.getSymbol() + " " + value;
        return Constant.messages.getString(
                "automation.tests.stats.pass", jobType, name, testPassedReason);
    }

    @Override
    protected String getTestFailedMessage() {
        String testFailedReason = stat + " " + getInverseOperator().getSymbol() + " " + value;
        return Constant.messages.getString(
                "automation.tests.stats.fail", jobType, name, testFailedReason);
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
