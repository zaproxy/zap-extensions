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
import java.util.List;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.http.ComparableResponse;
import org.zaproxy.zap.extension.ascanrules.sqli.DbErrorSignatures;
import org.zaproxy.zap.extension.ascanrules.sqli.DbErrorSignatures.Dbms;
import org.zaproxy.zap.extension.ascanrules.sqli.DetectionStrategy;
import org.zaproxy.zap.extension.ascanrules.sqli.ScanContext;

/**
 * Detects UNION-based SQL injection using two complementary approaches:
 *
 * <p><strong>Error-based detection (primary):</strong> Appends UNION clauses and checks for
 * database-specific UNION error signatures. Uses exact UNION-specific fragments per engine
 * (verified from baseline rule 40018), filtering by {@link ScanContext#getTechSet()}.
 *
 * <p><strong>Response-differentiation detection (fallback):</strong> If error-based detection
 * fails, compares baseline vs UNION response for observable differences. Catches cases where
 * UNION succeeds silently (200 OK with different data), common in search/filter contexts.
 *
 * <p>Match rule: Error detection requires UNION-specific fragment absent from baseline AND
 * present in attack. Response-diff requires responses to differ significantly (via exact matching
 * after encoding stripping), indicating successful UNION injection altering result set.
 */
public class UnionBasedDetectionStrategy implements DetectionStrategy {

    /** The 6 core UNION appendages from baseline rule 40018. */
    private static final List<String> SQL_UNION_APPENDAGES =
            List.of(
                    " UNION ALL select NULL -- ",
                    "' UNION ALL select NULL -- '",
                    "\" UNION ALL select NULL -- \"",
                    ") UNION ALL select NULL -- ",
                    "') UNION ALL select NULL -- '",
                    "\") UNION ALL select NULL -- \"");

    @Override
    public boolean detect(ScanContext context) throws IOException {
        String originalValue =
                context.getOriginalValue() == null ? "" : context.getOriginalValue();
        int budget = context.getRemainingBudget();

        // Get candidate engines in scope for this target
        List<Dbms> candidates = DbErrorSignatures.inTechScope(context.getTechSet());
        if (candidates.isEmpty()) {
            // No candidates in tech scope, skip (zero requests spent, budget rolls to next strategy)
            return false;
        }

        // Send baseline with original value
        HttpMessage baseline = context.newMessage();
        context.setParam(baseline, originalValue);
        context.sendAndReceive(baseline);
        String baselineBody = baseline.getResponseBody().toString();
        String baselineStripped = ResponseBodyUtils.stripAllEncodedForms(baselineBody, originalValue);

        ComparableResponse baselineResp = new ComparableResponse(baseline, originalValue);

        int used = 1;
        HttpMessage lastUnionMsg = null;
        String lastUnionPayload = null;

        for (String appendage : SQL_UNION_APPENDAGES) {
            if (context.isStopped() || used >= budget) {
                return false;
            }

            String payload = originalValue + appendage;
            HttpMessage attackMsg = context.newMessage();
            context.setParam(attackMsg, payload);
            context.sendAndReceive(attackMsg);
            used++;

            String attackBody = attackMsg.getResponseBody().toString();
            String attackStripped = ResponseBodyUtils.stripAllEncodedForms(attackBody, originalValue, payload);

            // Try error-based detection first (fast path)
            boolean errorDetected = false;
            for (Dbms dbms : candidates) {
                for (String unionFragment : dbms.getUnionFragments()) {
                    // Fragment absent from baseline AND present in attack => hit
                    boolean absentFromBaseline = !baselineStripped.contains(unionFragment);
                    boolean presentInAttack = attackStripped.contains(unionFragment);
                    if (absentFromBaseline && presentInAttack) {
                        context.newAlert()
                                .setConfidence(Alert.CONFIDENCE_HIGH)
                                .setParam(context.getParamName())
                                .setAttack(payload)
                                .setEvidence(unionFragment)
                                .setOtherInfo("Likely RDBMS: " + dbms.getLabel())
                                .setMessage(attackMsg)
                                .raise();
                        return true;
                    }
                }
            }

            // Save last attempt for response-differentiation fallback
            lastUnionMsg = attackMsg;
            lastUnionPayload = payload;
        }

        // Fallback: Response-differentiation detection for cases where UNION succeeds silently
        // (200 OK but different data). Common in search/filter contexts (200Valid cases).
        if (lastUnionMsg != null) {
            ComparableResponse unionResp = new ComparableResponse(lastUnionMsg, lastUnionPayload);
            float similarity = baselineResp.compareWith(unionResp);

            // If responses differ significantly (0.01 < similarity < 0.80), UNION likely altered result set
            // Skip 0% similarity (trap signature: completely broken response from security frameworks)
            // and >0.80 (too similar, likely not an injection)
            // This range catches legitimate 200Valid Search-Union cases while avoiding
            // HoneyPot/PsAndIv false positives that return 0% similarity
            if (similarity > 0.0f && similarity < 0.80f) {
                context.newAlert()
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setParam(context.getParamName())
                        .setAttack(lastUnionPayload)
                        .setOtherInfo("UNION-based SQLi: response differs from baseline (similarity: "
                                + String.format("%.0f", similarity * 100) + "%)")
                        .setMessage(lastUnionMsg)
                        .raise();
                return true;
            }
        }

        return false;
    }
}
