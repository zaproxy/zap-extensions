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
 * Thin wrapper around commonlib's {@link ComparableResponse} fuzzy-diff heuristic (already used by
 * 40018 -- a known quantity, not extra risk to pull in).
 *
 * <p><strong>Caveat:</strong> this being a reasonable choice is proven against WAVSEP specifically.
 * WAVSEP's case labels (which pages are genuinely vulnerable) are solid ground truth verified
 * directly against the running app, but that doesn't make this comparison heuristic automatically
 * correct for every target. It's kept behind this one class, on the other side of the {@link
 * DetectionStrategy} seam, specifically so it can be swapped or rethought once validation moves on
 * to other test beds, without that decision leaking into the rest of the rule.
 */
public class ResponseComparator {

    /**
     * Similarity score (from {@link ComparableResponse#compareWith}) at or above which two
     * responses are considered the same outcome. 0 means very different, 1 means very similar.
     */
    private static final float SIMILARITY_THRESHOLD = 0.98f;
    private static final float FUZZY_TUNED_THRESHOLD = 0.97f;

    /** Whether {@code a} and {@code b} represent essentially the same response. */
    public boolean isSimilar(HttpMessage a, String aValue, HttpMessage b, String bValue) {
        return similarity(a, aValue, b, bValue) >= SIMILARITY_THRESHOLD;
    }

    /** Whether {@code a} and {@code b} represent meaningfully different responses. */
    public boolean isDifferent(HttpMessage a, String aValue, HttpMessage b, String bValue) {
        return !isSimilar(a, aValue, b, bValue);
    }

    /**
     * Fuzzy similarity with tuned heuristics: creates two ComparableResponse objects, tunes their
     * weights based on each other, then compares them. More adaptive than strict matching but
     * retains fidelity through weight tuning.
     */
    public boolean isSimilarTuned(HttpMessage a, String aValue, HttpMessage b, String bValue) {
        return similarityTuned(a, aValue, b, bValue) >= FUZZY_TUNED_THRESHOLD;
    }

    /** Negation of isSimilarTuned for boolean logic. */
    public boolean isDifferentTuned(HttpMessage a, String aValue, HttpMessage b, String bValue) {
        return !isSimilarTuned(a, aValue, b, bValue);
    }

    /**
     * Compares two responses for exact equality after stripping the original value and the value
     * sent in all their encoded forms. Status codes must match; bodies are stripped of the
     * patterns and compared with binary equality. For redirect responses (3xx), also checks that
     * Location headers match (mirroring baseline's locationHeaderHeuristic).
     *
     * @param a the first message
     * @param aOriginalValue the original parameter value for message a
     * @param aValueSent the value actually sent in the request for message a
     * @param b the second message
     * @param bOriginalValue the original parameter value for message b
     * @param bValueSent the value actually sent in the request for message b
     * @return true if status codes are equal, Location headers match (if both are redirects), and
     *     response bodies match after stripping, false otherwise
     */
    public boolean matchesExactlyAfterStripping(
            HttpMessage a,
            String aOriginalValue,
            String aValueSent,
            HttpMessage b,
            String bOriginalValue,
            String bValueSent) {
        int statusA = a.getResponseHeader().getStatusCode();
        int statusB = b.getResponseHeader().getStatusCode();
        if (statusA != statusB) {
            return false;
        }

        // For redirects (3xx), also check Location header equality
        if (statusA >= 300 && statusA < 400) {
            String locationA = a.getResponseHeader().getHeader("Location");
            String locationB = b.getResponseHeader().getHeader("Location");
            if (!equals(locationA, locationB)) {
                return false;
            }
        }

        String aBody = a.getResponseBody().toString();
        String bBody = b.getResponseBody().toString();

        String aStripped =
                ResponseBodyUtils.stripAllEncodedForms(
                        aBody, aOriginalValue, aValueSent);
        String bStripped =
                ResponseBodyUtils.stripAllEncodedForms(
                        bBody, bOriginalValue, bValueSent);

        return aStripped.equals(bStripped);
    }

    private static boolean equals(String a, String b) {
        return (a == null && b == null) || (a != null && a.equals(b));
    }

    private float similarity(HttpMessage a, String aValue, HttpMessage b, String bValue) {
        ComparableResponse responseA = new ComparableResponse(a, aValue);
        ComparableResponse responseB = new ComparableResponse(b, bValue);
        return responseA.compareWith(responseB);
    }

    private float similarityTuned(HttpMessage a, String aValue, HttpMessage b, String bValue) {
        ComparableResponse responseA = new ComparableResponse(a, aValue);
        ComparableResponse responseB = new ComparableResponse(b, bValue);
        // Tune weights based on each other for more adaptive comparison
        responseA.tuneHeuristicsWithResponse(responseB);
        responseB.tuneHeuristicsWithResponse(responseA);
        return responseA.compareWith(responseB);
    }
}
