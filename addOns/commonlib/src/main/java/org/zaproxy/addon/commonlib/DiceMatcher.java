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
package org.zaproxy.addon.commonlib;

import java.util.Arrays;

/**
 * A {@code DiceMatcher} that implements the Dice algorithm to measure the similarity between two
 * strings
 *
 * @since 1.3.0
 */
public final class DiceMatcher {

    private DiceMatcher() {}

    /**
     * @param a The first string to be compared
     * @param b The second string to be compared
     * @return The match percentage of the two strings, rounded off to the nearest integer
     */

    /*
     * Source : https://en.wikibooks.org/wiki/Algorithm_Implementation/Strings/Dice%27s_coefficient
     * License :  https://creativecommons.org/licenses/by-sa/3.0/
     * Author : Jelle Fresen
     * Changes : Fixed indexing to prevent out of array access
     *           Address various issues identified by static analysis
     * Released under CC-BY-SA.
     */

    public static int getMatchPercentage(String a, String b) {

        if (a == null || b == null) return 0;

        String s = a.replaceAll("\\s+", " ");
        String t = b.replaceAll("\\s+", " ");

        // Quick check to catch equal strings:
        if (s.equals(t)) return 100;
        // avoid exception for single character searches
        if (s.length() < 2 || t.length() < 2) return 0;

        final int[] sPairs = getBigrams(s);
        final int[] tPairs = getBigrams(t);

        // Sort the bigram arrays:
        Arrays.sort(sPairs);
        Arrays.sort(tPairs);

        // Count the matches:
        int matches = 0;
        int i = 0;
        int j = 0;
        int n = s.length() - 1;
        int m = t.length() - 1;
        while (i < n && j < m) {
            if (sPairs[i] == tPairs[j]) {
                matches += 2;
                i++;
                j++;
            } else if (sPairs[i] < tPairs[j]) i++;
            else j++;
        }
        return (int) Math.floor((double) matches * 100 / (n + m));
    }

    private static int[] getBigrams(String str) {
        final int n = str.length() - 1;
        final int[] pairs = new int[n];
        for (int i = 0; i < n; i++)
            if (i == 0) pairs[i] = str.charAt(i) << 16;
            else if (i == n - 1) pairs[i - 1] |= str.charAt(i);
            else {
                int p = pairs[i - 1] | str.charAt(i);
                pairs[i - 1] = p;
                pairs[i] = p << 16;
            }
        return pairs;
    }
}
