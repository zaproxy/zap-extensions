/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
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
package org.zaproxy.zap.extension.tokengen;

import java.util.List;
import java.util.ResourceBundle;

public class TokenAnalysisTestResult {

    public enum Type {
        MAX_ENTROPY,
        CHR_UNIFORMITY,
        CHR_TRANSITIONS,
        COUNT_1_BIT,
        COUNT_2_BITS,
        COUNT_3_BITS,
        COUNT_4_BITS,
        COUNT_8_BITS,
        COUNT_16_BITS
    }

    public enum Result {
        FAIL,
        LOW,
        MEDIUM,
        HIGH,
        PASS
    }

    private static ResourceBundle resourceBundle;

    private static final String BASE_RSRC_KEY = "tokengen.analyse.test.";

    private Type type;
    private String name;
    private String summary;
    private Result result;
    private List<String> details;
    private List<String> failures;

    public TokenAnalysisTestResult(Type type) {
        this.type = type;
        this.name =
                resourceBundle != null
                        ? resourceBundle.getString(BASE_RSRC_KEY + type.name().toLowerCase())
                        : type.name();
    }

    public Type getType() {
        return type;
    }

    public String getName() {
        return name;
    }

    public String getSummary() {
        return summary;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }

    public Result getResult() {
        return result;
    }

    public void setResult(Result result) {
        this.result = result;
    }

    public List<String> getDetails() {
        return details;
    }

    public void setDetails(List<String> details) {
        this.details = details;
    }

    public List<String> getFailures() {
        return failures;
    }

    public void setFailures(List<String> failures) {
        this.failures = failures;
    }

    /**
     * Sets the {@code ResourceBundle} used to obtain the internationalised name of the result.
     *
     * <p>It's used the {@link TokenAnalysisTestResult.Type Type}'s name if no {@code
     * ResourceBundle} is set.
     *
     * @param resourceBundle the {@code ResourceBundle} to obtain the name of the result
     * @see #getName()
     */
    static void setResourceBundle(ResourceBundle resourceBundle) {
        TokenAnalysisTestResult.resourceBundle = resourceBundle;
    }
}
