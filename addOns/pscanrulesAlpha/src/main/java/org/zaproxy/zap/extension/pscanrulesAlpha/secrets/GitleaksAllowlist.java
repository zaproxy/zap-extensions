/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrulesAlpha.secrets;

import com.google.re2j.Pattern;
import java.util.List;
import java.util.Locale;

/**
 * A Gitleaks allowlist, which holds what to ignore: findings which match its regexes or have one of
 * its stopwords, and requests with one of its paths.
 *
 * <p>Only the parts which apply to HTTP responses are supported, there are no commits. The
 * allowlists which check the whole line, or which need all of the criteria to match (a condition of
 * {@code AND}), are not supported, see {@link GitleaksConfigLoader}.
 */
public class GitleaksAllowlist {

    private final List<Pattern> regexes;
    private final List<String> stopwords;
    private final List<Pattern> paths;
    private final boolean regexesOnMatch;

    /**
     * Constructs an allowlist.
     *
     * @param regexes the regexes which allow a finding.
     * @param stopwords the lower case words which allow a finding with a secret that has them.
     * @param paths the regexes which allow all the findings of a request with a matching path.
     * @param regexesOnMatch {@code true} to check the regexes against the whole match, {@code
     *     false} to check them against the secret.
     */
    GitleaksAllowlist(
            List<Pattern> regexes,
            List<String> stopwords,
            List<Pattern> paths,
            boolean regexesOnMatch) {
        this.regexes = regexes;
        this.stopwords = stopwords;
        this.paths = paths;
        this.regexesOnMatch = regexesOnMatch;
    }

    /**
     * Tells whether the path allows all the findings, in which case the content does not need to be
     * scanned. If there are no paths, or none match, the content still has to be scanned.
     *
     * @param path the path of the request, {@code null} if the paths are not used.
     */
    public boolean allowsPath(String path) {
        return path != null && anyMatch(paths, path);
    }

    /** Tells whether the given finding is allowed, by the regexes or the stopwords. */
    boolean allows(String match, String secret) {
        return anyMatch(regexes, regexesOnMatch ? match : secret) || matchesStopword(secret);
    }

    private static boolean anyMatch(List<Pattern> patterns, String text) {
        return patterns.stream().anyMatch(pattern -> pattern.matcher(text).find());
    }

    private boolean matchesStopword(String secret) {
        String lower = secret.toLowerCase(Locale.ROOT);
        return stopwords.stream().anyMatch(lower::contains);
    }
}
