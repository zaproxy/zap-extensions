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
package org.zaproxy.zap.extension.wappalyzer;

import com.google.re2j.Pattern;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;

public class AppPattern {

    private String type = null;
    private Pattern re2jPattern = null;
    private java.util.regex.Pattern javaPattern = null;
    private String version = null;
    private int confidence = 100;

    public void setPattern(String pattern) {
        this.javaPattern = java.util.regex.Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
        try {
            // This takes precedence, if it compiles
            this.re2jPattern = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
        } catch (com.google.re2j.PatternSyntaxException e) {
            // Ignore
        }
    }
    /**
     * Returns the java version of the regex pattern - its provided as the core requires a java
     * Pattern when searching for evidence. It should not be used for matching in this package, use
     * findInString instead for performance reasons.
     *
     * @return
     */
    public java.util.regex.Pattern getJavaPattern() {
        return javaPattern;
    }

    public Pattern getRe2jPattern() {
        return re2jPattern;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public int getConfidence() {
        return confidence;
    }

    public void setConfidence(int confidence) {
        this.confidence = confidence;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public List<String> findInString(String str) {
        List<String> results = null;
        if (this.re2jPattern != null) {
            com.google.re2j.Matcher re2jMatcher = this.re2jPattern.matcher(str);
            if (re2jMatcher.find()) {
                results = createResultsList(re2jMatcher.groupCount());
                for (int i = 1; i <= re2jMatcher.groupCount(); i++) {
                    addGroup(re2jMatcher.group(i), results);
                }
            }
        } else {
            Matcher matcher = this.javaPattern.matcher(str);
            if (matcher.find()) {
                results = createResultsList(matcher.groupCount());
                for (int i = 1; i <= matcher.groupCount(); i++) {
                    addGroup(matcher.group(i), results);
                }
            }
        }
        return results;
    }

    private List<String> createResultsList(int size) {
        if (size == 0) {
            return Collections.emptyList();
        }
        return new ArrayList<>(size);
    }

    private void addGroup(String group, List<String> results) {
        if (group == null) {
            return;
        }
        String trimmedGroup = group.trim();
        if (!trimmedGroup.isEmpty()) {
            results.add(trimmedGroup);
        }
    }
}
