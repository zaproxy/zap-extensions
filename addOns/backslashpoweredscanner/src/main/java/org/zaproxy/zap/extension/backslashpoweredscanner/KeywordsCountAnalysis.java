/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.backslashpoweredscanner;

import java.util.HashMap;
import org.apache.commons.lang.StringUtils;
import org.zaproxy.zap.network.HttpResponseBody;

class KeywordsCountAnalysis {
    static final String[] keywords = {
        "</html>",
        "error",
        "exception",
        "invalid",
        "warning",
        "stack",
        "sql syntax",
        "divisor",
        "divide",
        "ora-",
        "division",
        "infinity",
        "<script",
        "<div"
    };
    private HashMap<String, Integer> keywordsCounts;

    public KeywordsCountAnalysis() {
        this.keywordsCounts = new HashMap<>();
    }

    public KeywordsCountAnalysis(HttpResponseBody responseBody) {
        this.keywordsCounts = new HashMap<>();
        String body = responseBody.toString();
        for (String keyword : keywords) {
            keywordsCounts.put(keyword, StringUtils.countMatches(body, keyword));
        }
    }

    public HashMap<String, Integer> getKeywordsCounts() {
        return keywordsCounts;
    }

    public void analyzeKeywordsCounts(HttpResponseBody responseBody) {
        String body = responseBody.toString();
        for (String keyword : keywords) {
            keywordsCounts.put(keyword, StringUtils.countMatches(body, keyword));
        }
    }

    public void updateWith(HttpResponseBody responseBody) {
        updateWith(new KeywordsCountAnalysis(responseBody).getKeywordsCounts());
    }

    public void updateWith(HashMap<String, Integer> keywordsCounts) {
        HashMap<String, Integer> newKeywordsCounts = new HashMap<>();
        for (String name : this.keywordsCounts.keySet()) {
            if (this.keywordsCounts.containsKey(name)
                    && this.keywordsCounts.get(name).equals(keywordsCounts.get(name))) {
                newKeywordsCounts.put(name, this.keywordsCounts.get(name));
            }
        }
        this.keywordsCounts = newKeywordsCounts;
    }
}
