/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.sqliplugin;

import java.util.HashMap;
import java.util.Map;

/**
 * Class for string diff management used to compare the original content to the one related to a
 * specific evil payload. The internal algorithm is based upon one published in the late 1980's by
 * Ratcliff and Obershelp under the hyperbolic name "gestalt pattern matching". The idea is to find
 * the longest contiguous matching subsequence that contains no "junk" elements.
 *
 * @author yhawke (2013)
 */
public class ResponseMatcher {
    // Minimum distance of ratio from kb.matchRatio to result in True
    public static final double DIFF_TOLERANCE = 0.05;
    public static final double CONSTANT_RATIO = 0.9;

    // Lower and upper values for match ratio in case of stable page
    public static final double LOWER_RATIO_BOUND = 0.02;
    public static final double UPPER_RATIO_BOUND = 0.98;

    // Minimum value for comparison ratio
    public static final double MIN_RATIO = 0.0;

    // Maximum value for comparison ratio
    public static final double MAX_RATIO = 1.0;

    private String strA;
    private String strB;
    // Inner helper class for strB string counting
    private Map<Integer, Integer> fullBCount;
    private double matchRatio;
    private boolean negativeLogic;

    public ResponseMatcher() {
        fullBCount = new HashMap<>();
        matchRatio = -1;
        negativeLogic = false;
    }

    /** @param strA */
    public void setInjectedResponse(String a) {
        this.strA = a;
    }

    /** @param strB */
    public void setOriginalResponse(String b) {
        this.strB = b;
        this.fullBCount.clear();
        matchRatio = -1;
    }

    /** @param replacementMode */
    public void setLogic(int replacementMode) {
        this.negativeLogic = (replacementMode == SQLiPayloadManager.WHERE_NEGATIVE);
    }

    /**
     * Return an upper bound on ratio() relatively quickly. This isn't defined beyond that it is an
     * upper bound and is faster to compute.
     *
     * @return
     */
    public double getQuickRatio() {
        int chr;
        int count;
        int matches = 0;
        int start = 0;
        while (start < Math.min(strA.length(), strB.length())) {
            if (strA.charAt(start) == strB.charAt(start)) {
                start += 1;

            } else break;
        }

        // viewing strA and strB as multisets, set matches to the cardinality
        // of their intersection; this counts the number of matches
        // without regard to order, so is clearly an upper bound
        if (fullBCount.isEmpty()) {

            for (int i = start; i < strB.length(); i++) {
                chr = strB.charAt(i);
                count = fullBCount.containsKey(chr) ? fullBCount.get(chr) : 1;
                fullBCount.put(chr, count);
            }
        }

        // avail[x] is the number of times x appears in 'strB' less the
        // number of times we've seen it in 'strA' so far ... kinda
        Map<Integer, Integer> avail = new HashMap<>();

        for (int i = start; i < strA.length(); i++) {
            chr = strA.charAt(i);
            if (avail.containsKey(chr)) {
                count = avail.get(chr);

            } else if (fullBCount.containsKey(chr)) {
                count = fullBCount.get(chr);

            } else {
                count = 0;
            }

            avail.put(chr, count - 1);

            if (count > 0) {
                matches += 1;
            }
        }

        int totalLength = strA.length() + strB.length();

        return (totalLength > 0) ? 2.0 * (start + matches) / totalLength : 1.0;
    }

    /**
     * @param where
     * @return
     */
    public boolean isComparable() {
        double ratio = getQuickRatio();

        // If comparison has never been done
        // set it as base ratio value
        if (matchRatio < 0) matchRatio = ratio;

        boolean comparable =
                ((ratio > UPPER_RATIO_BOUND) || ((ratio - matchRatio) > DIFF_TOLERANCE));

        // Test if we need strA negative logic approach.
        // This is used in raw page comparison scheme as that what is "different" than original
        // WHERE_NEGATIVE response is considered as True; in switch based approach negative logic
        // is not applied as that what is by user considered as True is that what is returned
        // by the comparison mechanism itself
        return negativeLogic ^ comparable;
    }
}
