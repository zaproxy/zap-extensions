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
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.parosproxy.paros.Constant;

public final class RegexTester {

    private RegexTester() {}

    public static RegexTestResult test(RegexTestInput input) {
        try {
            return testInternal(input);
        } catch (Exception e) {
            return new RegexTestResult(false, false, e.getMessage(), "");
        }
    }

    private static RegexTestResult testInternal(RegexTestInput input) {
        Pattern compiledPattern = Pattern.compile(input.getPattern());
        Matcher matcher = compiledPattern.matcher(input.getText());
        boolean match = matcher.matches();
        boolean lookingAt = matcher.lookingAt();

        List<RegexTestResult.Group> highlights = new ArrayList<>();
        Matcher findMatcher = compiledPattern.matcher(input.getText());
        StringBuilder capture = new StringBuilder();
        int findIndex = 1;
        boolean matcherFound = false;
        while (findMatcher.find()) {
            highlights.add(new RegexTestResult.Group(findMatcher.start(), findMatcher.end()));
            appendFind(findMatcher, findIndex, capture);
            appendAllGroups(findMatcher, findIndex, capture);
            capture.append("\n");
            findIndex++;
            matcherFound = true;
        }

        if (!matcherFound) {
            return new RegexTestResult(
                    match, lookingAt, Constant.messages.getString("regextester.result.none"), "");
        }

        return new RegexTestResult(
                match, lookingAt, input.getText(), capture.toString().trim(), highlights);
    }

    private static void appendFind(Matcher matcher, int findIndex, StringBuilder capture) {
        capture.append(findIndex).append("   ");
        buildGroup(capture, matcher, 0);
    }

    private static void appendAllGroups(Matcher matcher, int findIndex, StringBuilder capture) {
        for (int i = 1; i <= matcher.groupCount(); i++) {
            capture.append("").append(findIndex).append(".").append(i).append(" ");
            buildGroup(capture, matcher, i);
        }
    }

    private static void buildGroup(StringBuilder capture, Matcher matcher, int index) {
        capture.append("[")
                .append(matcher.start(index))
                .append(",")
                .append(matcher.end(index))
                .append("]")
                .append("\t")
                .append(matcher.group(index))
                .append("\n");
    }
}
