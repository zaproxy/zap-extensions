/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.fuzz.httpfuzzer.processors.tagcreator;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.parosproxy.paros.Constant;

public class MatchByRegexTagRule extends RegexTagRule {

    private String tag;

    public MatchByRegexTagRule(String regex, String tag) {
        super(regex);
        this.tag = tag;
    }

    public String getTag() {
        return tag;
    }

    @Override
    public String getName() {
        String ruleName =
                Constant.messages.getString(
                        "fuzz.httpfuzzer.processor.tagcreator.matchbyregex.name");
        return tag + "; " + ruleName + " " + getRegex();
    }

    @Override
    public String createTag(String responseMessage) {
        if (isHttpResponseMatching(responseMessage)) {
            return getTag();
        }
        return null;
    }

    private boolean isHttpResponseMatching(String responseMessage) {
        return hasRegex() && matchByRegex(responseMessage);
    }

    private boolean matchByRegex(String responseMessage) {
        Pattern pattern = getRegexPattern();
        Matcher matcher = pattern.matcher(responseMessage);
        return matcher.find();
    }
}
