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
package org.zaproxy.zap.extension.authenticationhelper;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.apache.commons.configuration.FileConfiguration;
import org.parosproxy.paros.common.AbstractParam;

public class OptionsParamAuthenticationHelper extends AbstractParam {

    private static final String CONFIRM_REMOVE_EXCLUDE_REGEX_KEY =
            "authenticationhelper.confirmRemoveProxyExcludeRegex";
    private static final String REGEXES_TO_IGNORE_KEY = "authenticationhelper.regexestoignore";

    private boolean confirmRemoveExcludeRegex;
    private List<String> regexesToIgnore;

    private static final String[] DEFAULT_PATTERNS_TO_IGNORE = {
        ".*.css", ".*.js", ".*.jpeg", ".*.jpg", ".*.png", ".*.ico", ".*logout.*", ".*login.*"
    };

    public OptionsParamAuthenticationHelper() {}

    @SuppressWarnings("unchecked")
    @Override
    protected void parse() {
        FileConfiguration cfg = getConfig();
        confirmRemoveExcludeRegex = cfg.getBoolean(CONFIRM_REMOVE_EXCLUDE_REGEX_KEY, false);
        regexesToIgnore = (List<String>) (List<?>) cfg.getList(REGEXES_TO_IGNORE_KEY);
        addDefaultIgnoredRegexes();
    }

    private void addDefaultIgnoredRegexes() {
        regexesToIgnore.addAll(Arrays.asList(DEFAULT_PATTERNS_TO_IGNORE));
        regexesToIgnore = regexesToIgnore.stream().distinct().collect(Collectors.toList());
    }

    public boolean isConfirmRemoveExcludeRegex() {
        return confirmRemoveExcludeRegex;
    }

    public void setConfirmRemoveExcludeRegex(boolean confirmRemove) {
        this.confirmRemoveExcludeRegex = confirmRemove;
        getConfig().setProperty(CONFIRM_REMOVE_EXCLUDE_REGEX_KEY, Boolean.valueOf(confirmRemove));
    }

    public List<String> getRegexesToIgnore() {
        return regexesToIgnore;
    }

    public void setRegexesToIgnore(List<String> regexesToIgnore) {
        addDefaultIgnoredRegexes();
        getConfig().setProperty(REGEXES_TO_IGNORE_KEY, regexesToIgnore);
    }

    public List<Pattern> getRexesPatternsToIgnore() {
        List<Pattern> regexPatternsToIgnore = new ArrayList<>();
        for (String regex : regexesToIgnore) {
            if (regex.trim().length() > 0) {
                regexPatternsToIgnore.add(Pattern.compile(regex.trim(), Pattern.CASE_INSENSITIVE));
            }
        }
        return regexPatternsToIgnore;
    }
}
