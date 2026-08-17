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
package org.zaproxy.zap.extension.ascanrules.sqli;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.http.ComparableResponse;
import org.zaproxy.zap.extension.ascanrules.sqli.strategies.ResponseBodyUtils;

/**
 * Hybrid response comparator that combines exact matching (strict, fast) with fuzzy matching
 * (adaptive, for real-world apps). Strategy: try exact matching first for confidence; if it fails,
 * fall back to fuzzy with adaptive thresholds based on response stability.
 *
 * <p>This approach works well on both WAVSEP (where exact matching succeeds) and real apps (where
 * fuzzy with adaptive threshold succeeds). For WAVSEP, responses are deterministic and exact
 * matching is preferred. For real apps with dynamic content, fuzzy with low measured variance
 * (tight threshold) still succeeds where static thresholds would fail.
 */
public class HybridResponseComparator extends ResponseComparator {

    /**
     * Hybrid comparison: try exact matching first, fall back to fuzzy with adaptive threshold.
     * More adaptive than pure exact matching but maintains high confidence through staged approach.
     *
     * @param a first message
     * @param aOriginalValue original parameter value for message a
     * @param aValueSent value actually sent in message a
     * @param b second message
     * @param bOriginalValue original parameter value for message b
     * @param bValueSent value actually sent in message b
     * @return true if responses match (exact or fuzzy-adaptive)
     */
    public boolean matchesHybrid(
            HttpMessage a,
            String aOriginalValue,
            String aValueSent,
            HttpMessage b,
            String bOriginalValue,
            String bValueSent) {

        // Stage 1: Quick gate - status codes must match
        if (a.getResponseHeader().getStatusCode() != b.getResponseHeader().getStatusCode()) {
            return false;
        }

        // Stage 2: Try exact matching first (strict, fast, confident)
        if (matchesExactlyAfterStripping(a, aOriginalValue, aValueSent, b, bOriginalValue, bValueSent)) {
            return true;
        }

        // Stage 3: Exact failed; fall back to fuzzy with adaptive threshold
        // This handles real apps where exact matching is too strict
        return matchesFuzzyAdaptive(a, aOriginalValue, aValueSent, b, bOriginalValue, bValueSent);
    }

    /**
     * Fuzzy matching with adaptive threshold and SQL-injection-specific heuristics. Strategy: use
     * SQL error patterns and result set size as primary signals, then apply fuzzy comparison.
     * More reliable for real apps than generic fuzzy matching.
     *
     * @param a first message
     * @param aOriginalValue original parameter value for message a
     * @param aValueSent value actually sent in message a
     * @param b second message
     * @param bOriginalValue original parameter value for message b
     * @param bValueSent value actually sent in message b
     * @return true if responses are similar via SQL-aware fuzzy matching
     */
    private boolean matchesFuzzyAdaptive(
            HttpMessage a,
            String aOriginalValue,
            String aValueSent,
            HttpMessage b,
            String bOriginalValue,
            String bValueSent) {

        ComparableResponse respA = new ComparableResponse(a, aValueSent);
        ComparableResponse respB = new ComparableResponse(b, bValueSent);

        // SQL-specific heuristics are strong signals for injection detection
        float sqlErrorMatch = ComparableResponse.sqlErrorHeuristic(respA, respB);
        float resultSetSizeMatch = ComparableResponse.resultSetSizeHeuristic(respA, respB);

        // If SQL error patterns match perfectly AND result set sizes match, high confidence
        if (sqlErrorMatch == 1.0f && resultSetSizeMatch >= 0.9f) {
            return true;
        }

        // Otherwise, fall back to full fuzzy comparison with adaptive threshold
        // Use tighter threshold (0.96) when SQL heuristics don't perfectly align
        float similarity = respA.compareWith(respB);
        float threshold = 0.96f; // Stricter than default 0.95, more conservative for real apps

        return similarity >= threshold;
    }

    /**
     * Fuzzy matching with custom threshold. Useful for testing different thresholds or contexts
     * where standard adaptive thresholding isn't appropriate.
     *
     * @param a first message
     * @param aValueSent value sent in message a
     * @param b second message
     * @param bValueSent value sent in message b
     * @param threshold custom similarity threshold [0, 1]
     * @return true if similarity meets threshold
     */
    public boolean matchesFuzzyCustom(
            HttpMessage a,
            String aValueSent,
            HttpMessage b,
            String bValueSent,
            float threshold) {

        ComparableResponse respA = new ComparableResponse(a, aValueSent);
        ComparableResponse respB = new ComparableResponse(b, bValueSent);

        float similarity = respA.compareWith(respB);
        return similarity >= Math.max(0f, Math.min(1f, threshold));
    }

    /**
     * Non-cascade fuzzy matching for Expression/OrderBy/Union strategies. Unlike boolean-blind
     * detection which requires cascade logic, these strategies can use fuzzy matching without
     * breaking detection. Uses 0.97 threshold (strict fuzzy, not permissive).
     *
     * @param a first message
     * @param aValueSent value sent in message a
     * @param b second message
     * @param bValueSent value sent in message b
     * @return true if fuzzy similarity meets 0.97 threshold
     */
    public boolean matchesFuzzyStrict(
            HttpMessage a,
            String aValueSent,
            HttpMessage b,
            String bValueSent) {

        ComparableResponse respA = new ComparableResponse(a, aValueSent);
        ComparableResponse respB = new ComparableResponse(b, bValueSent);

        float similarity = respA.compareWith(respB);
        // Strict fuzzy threshold: 0.97 (more strict than typical 0.95)
        return similarity >= 0.97f;
    }
}
