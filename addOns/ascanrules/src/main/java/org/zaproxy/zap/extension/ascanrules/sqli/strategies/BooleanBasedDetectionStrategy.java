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
 * Detects boolean-based blind SQL injection using the restrict→broaden cascade: for each of 9
 * payload triples, tries AND_TRUE first; if it matches the baseline, tries AND_FALSE; if
 * AND_FALSE also matches (empty result set case), falls back to OR_TRUE. Alerts on the first
 * successful match (restrict-verify or broaden-verify path).
 *
 * <p>The 9 triples target string contexts (single/double quote, with/without trailing comment)
 * and numeric contexts, matching baseline rule 40018's empirical strategy. This expansion from
 * prior 2-payload approach unlocks detection of string/date parameter contexts.
 *
 * <p>Deliberately re-sends the original value rather than comparing against {@link
 * ScanContext#getBaseMessage()}: that message is whatever was last seen for this URL (in ZAP's
 * unit test harness it's not even a real response), so a live baseline is the only reliable
 * comparison point.
 */
public class BooleanBasedDetectionStrategy implements DetectionStrategy {

    private final ResponseComparator comparator = new ResponseComparator();

    @Override
    public boolean detect(ScanContext context) throws IOException {
        String originalValue =
                context.getOriginalValue() == null ? "" : context.getOriginalValue();
        int budget = context.getRemainingBudget();

        HttpMessage baseline = context.newMessage();
        context.setParam(baseline, originalValue);
        context.sendAndReceive(baseline);
        int used = 1;

        for (BooleanConditionPayloads.Condition condition : BooleanConditionPayloads.CONDITIONS) {
            if (context.isStopped() || used + 2 > budget) {
                return false;
            }

            String trueValue = originalValue + condition.andTrue();
            HttpMessage trueMsg = context.newMessage();
            context.setParam(trueMsg, trueValue);
            context.sendAndReceive(trueMsg);
            used++;

            boolean trueMatchesBaseline =
                    comparator.matchesExactlyAfterStripping(
                            baseline, originalValue, originalValue, trueMsg, originalValue, trueValue);

            if (!trueMatchesBaseline) {
                // AND_TRUE didn't match baseline, try next payload pair
                continue;
            }

            // AND_TRUE matches baseline; now test AND_FALSE
            if (used + 1 > budget) {
                return false;
            }

            String falseValue = originalValue + condition.andFalse();
            HttpMessage falseMsg = context.newMessage();
            context.setParam(falseMsg, falseValue);
            context.sendAndReceive(falseMsg);
            used++;

            boolean falseDiffersFromBaseline =
                    !comparator.matchesExactlyAfterStripping(
                            baseline, originalValue, originalValue, falseMsg, originalValue, falseValue);

            if (falseDiffersFromBaseline) {
                // Restrict-verify: AND_TRUE~baseline AND AND_FALSE!=baseline. Alert.
                context.newAlert()
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setParam(context.getParamName())
                        .setAttack(trueValue)
                        .setOtherInfo(
                                "Page results were successfully manipulated using the boolean"
                                        + " conditions ["
                                        + trueValue
                                        + "] and ["
                                        + falseValue
                                        + "]")
                        .setMessage(trueMsg)
                        .raise();
                return true;
            }

            // AND_FALSE also matches baseline (no distinguishing data). Try OR_TRUE fallback.
            if (used + 1 > budget) {
                return false;
            }

            String orValue = originalValue + condition.orTrue();
            HttpMessage orMsg = context.newMessage();
            context.setParam(orMsg, orValue);
            context.sendAndReceive(orMsg);
            used++;

            boolean orDiffersFromBaseline =
                    !comparator.matchesExactlyAfterStripping(
                            baseline, originalValue, originalValue, orMsg, originalValue, orValue);

            if (orDiffersFromBaseline) {
                // Broaden-verify: AND_FALSE~baseline BUT OR_TRUE!=baseline. Alert.
                context.newAlert()
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setParam(context.getParamName())
                        .setAttack(orValue)
                        .setOtherInfo(
                                "Page results were successfully manipulated using the boolean"
                                        + " conditions ["
                                        + orValue
                                        + "] (via OR-based fallback, original AND conditions matched/matched)")
                        .setMessage(orMsg)
                        .raise();
                return true;
            }

            // Neither restrict nor broaden path succeeded; try next payload pair
        }

        return false;
    }
}
