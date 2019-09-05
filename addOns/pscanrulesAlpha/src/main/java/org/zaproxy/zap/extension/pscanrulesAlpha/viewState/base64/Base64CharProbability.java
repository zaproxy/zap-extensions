/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrulesAlpha.viewState.base64;

import java.util.regex.Pattern;

public enum Base64CharProbability {
    DIGIT(Pattern.compile("[0-9]"), 10),
    ALPHABETICAL(Pattern.compile("[a-zA-Z]"), 52),
    LOWERCASE(Pattern.compile("[a-z]"), 26),
    UPPERCASE(Pattern.compile("[A-Z]"), 26);

    public final Pattern pattern;
    public final int charQuantityInSample64Chars;

    Base64CharProbability(Pattern pattern, int charQuantityInSample64Chars) {
        this.pattern = pattern;
        this.charQuantityInSample64Chars = charQuantityInSample64Chars;
    }

    /**
     * Does the base 64 encoded string actually contain the various characters that we might expect?
     * (note: we may not care, depending on the threshold set by the user)
     *
     * @param base64EvidenceString the string to test
     * @return true if the string contains no character of this class, false otherwise
     */
    private boolean hasNotThisCharClass(String base64EvidenceString) {
        return !pattern.matcher(base64EvidenceString).find();
    }

    /**
     * calculate the actual probability of a Base64 string of this length *not* containing a given
     * character class (digit/alphabetic/other Base64 character) right about now, I expect to get
     * flamed by the statistics geeks in our midst.. wait for it! :)
     *
     * @param base64EvidenceString the string to test
     * @return the probability of a Base64 string of this length *not* containing a given character
     *     class
     */
    public float calculateProbabilityOfNotContainingCharClass(String base64EvidenceString) {
        return (float) Math.pow(((float) 64 - 26) / 64, base64EvidenceString.length());
    }

    // if the String is unlikely to be Base64, given the distribution of the
    // characters
    // ie, less probable than the threshold probability controlled by the user, then
    // do not process it.
    public boolean isUnlikelyToBeBase64(String base64EvidenceString, float probabilityThreshold) {
        return hasNotThisCharClass(base64EvidenceString)
                && calculateProbabilityOfNotContainingCharClass(base64EvidenceString)
                < probabilityThreshold;
    }
}
