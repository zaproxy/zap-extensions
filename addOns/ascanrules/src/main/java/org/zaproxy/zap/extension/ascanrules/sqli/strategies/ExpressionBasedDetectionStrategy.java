/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrules.sqli.strategies;

import java.io.IOException;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.ascanrules.sqli.DetectionStrategy;
import org.zaproxy.zap.extension.ascanrules.sqli.ResponseComparator;
import org.zaproxy.zap.extension.ascanrules.sqli.ScanContext;

/**
 * Detects SQL injection by testing if numeric parameters are evaluated as expressions.
 * For example, if parameter "1" gives the same result as "3-2", the database is likely
 * evaluating the expression, suggesting SQL injection is possible.
 */
public class ExpressionBasedDetectionStrategy implements DetectionStrategy {

    private final ResponseComparator comparator = new ResponseComparator();

    @Override
    public boolean detect(ScanContext context) throws IOException {
        String originalValue =
                context.getOriginalValue() == null ? "" : context.getOriginalValue();

        // Only test for numeric parameters
        int paramAsInt;
        try {
            paramAsInt = Integer.parseInt(originalValue);
        } catch (NumberFormatException e) {
            return false;
        }

        int budget = context.getRemainingBudget();
        if (budget < 4) {
            return false; // Need at least 4 requests: baseline + 2 for ADD + 1 for MULT check
        }

        // Get baseline response
        HttpMessage baselineMsg = context.newMessage();
        context.setParam(baselineMsg, originalValue);
        context.sendAndReceive(baselineMsg);
        int used = 1;

        // Try ADD variant: if param is 1, try "3-2" and "4-2"
        try {
            int paramPlusTwo = Math.addExact(paramAsInt, 2);
            int paramPlusThree = Math.addExact(paramAsInt, 3);

            String addVariant1 = String.valueOf(paramPlusTwo) + "-2";
            String addVariant2 = String.valueOf(paramPlusThree) + "-2";

            if (used + 2 <= budget && testExpressionVariant(context, baselineMsg, originalValue,
                    addVariant1, addVariant2)) {
                return true;
            }
            used += 2;

            // Try MULT variant: if param is 1, try "2/2" and "4/2"
            if (used + 2 <= budget) {
                int paramMultTwo = Math.multiplyExact(paramAsInt, 2);
                int paramMultFour = Math.multiplyExact(paramAsInt, 4);

                String multVariant1 = String.valueOf(paramMultTwo) + "/2";
                String multVariant2 = String.valueOf(paramMultFour) + "/2";

                if (testExpressionVariant(context, baselineMsg, originalValue, multVariant1,
                        multVariant2)) {
                    return true;
                }
            }
        } catch (ArithmeticException e) {
            // Integer overflow, can't test this parameter
        }

        return false;
    }

    private boolean testExpressionVariant(ScanContext context, HttpMessage baselineMsg,
            String originalValue, String variant1, String variant2) throws IOException {
        // Test first variant
        HttpMessage msg1 = context.newMessage();
        context.setParam(msg1, variant1);
        context.sendAndReceive(msg1);

        boolean variant1MatchesBaseline =
                comparator.matchesExactlyAfterStripping(baselineMsg, originalValue, originalValue, msg1, originalValue, variant1);

        if (!variant1MatchesBaseline) {
            return false; // First variant doesn't match baseline, not a valid expression test
        }

        // Test second variant
        HttpMessage msg2 = context.newMessage();
        context.setParam(msg2, variant2);
        context.sendAndReceive(msg2);

        boolean variant2DiffersFromBaseline =
                !comparator.matchesExactlyAfterStripping(baselineMsg, originalValue, originalValue, msg2, originalValue, variant2);
        boolean variant2DiffersFromVariant1 = !comparator.matchesExactlyAfterStripping(msg1, originalValue, variant1, msg2,
                originalValue, variant2);

        if (variant2DiffersFromBaseline && variant2DiffersFromVariant1) {
            // Expressions are being evaluated: baseline = variant1 but both differ from variant2
            context.newAlert()
                    .setConfidence(Alert.CONFIDENCE_MEDIUM)
                    .setParam(context.getParamName())
                    .setAttack(variant1)
                    .setOtherInfo("Parameter evaluates SQL expressions: [" + originalValue
                            + "] == [" + variant1 + "] != [" + variant2 + "]")
                    .setMessage(msg1)
                    .raise();
            return true;
        }

        return false;
    }
}
