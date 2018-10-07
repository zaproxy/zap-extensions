/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.regextester;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class RegexTestResult {
    private boolean match;
    private boolean lookingAt;
    private String result;
    private String capture;
    private List<RegexTestHighlight> highlights;

    public RegexTestResult(boolean match, boolean lookingAt, String result, String capture) {
        this(match, lookingAt, result, capture, new ArrayList<>());
    }

    public RegexTestResult(
            boolean match,
            boolean lookingAt,
            String result,
            String capture,
            List<RegexTestHighlight> highlights) {
        Objects.requireNonNull(result, "result is null");
        Objects.requireNonNull(result, "capture is null");
        Objects.requireNonNull(result, "highlights is null");

        this.match = match;
        this.lookingAt = lookingAt;
        this.capture = capture;
        this.result = result;
        this.highlights = highlights;
    }

    public void add(RegexTestHighlight highlight) {
        this.highlights.add(highlight);
    }

    public boolean isMatch() {
        return match;
    }

    public boolean isLookingAt() {
        return lookingAt;
    }

    public String getResult() {
        return result;
    }

    public String getCapture() {
        return capture;
    }

    public List<RegexTestHighlight> getHighlights() {
        return highlights;
    }

    public static class RegexTestHighlight {

        private int start;
        private int end;

        public RegexTestHighlight(int start, int end) {
            this.start = start;
            this.end = end;
        }

        public int getStart() {
            return start;
        }

        public int getEnd() {
            return end;
        }
    }
}
