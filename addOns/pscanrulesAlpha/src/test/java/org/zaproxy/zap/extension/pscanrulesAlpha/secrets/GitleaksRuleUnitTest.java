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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.zaproxy.zap.extension.pscanrulesAlpha.secrets.GitleaksConfigLoaderUnitTest.FIXTURE;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.zaproxy.zap.extension.pscanrulesAlpha.secrets.GitleaksConfigLoader.Config;
import org.zaproxy.zap.extension.pscanrulesAlpha.secrets.GitleaksRule.Finding;

class GitleaksRuleUnitTest {

    private static final String BUNDLED =
            "/org/zaproxy/zap/extension/pscanrulesAlpha/resources/gitleaks.toml";
    private static final String SECRET = "tok_k3j9x0q8w7z1";
    private static final GitleaksAllowlist NO_ALLOWLIST =
            new GitleaksAllowlist(List.of(), List.of(), List.of(), false);

    private static Config load(String resource) throws IOException {
        try (InputStream is = GitleaksRuleUnitTest.class.getResourceAsStream(resource)) {
            return GitleaksConfigLoader.load(is);
        }
    }

    private static GitleaksRule rule(Config config, String id) {
        return config.rules().stream().filter(r -> r.getId().equals(id)).findFirst().orElseThrow();
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "abc[a-z]{0,50}x",
                "(?i)[\\w.-]{0,50}?(?:twitter)[\\s'\"]{0,3}([a-z0-9]{35,44})",
                "[a-z+*]{3}",
                "\\+\\*",
                "a+",
                "[a-z]+",
                "[a-z]{3,}",
                "\\w*",
                "\\p{L}{3}",
                "\\x{41}abc",
                "{name}abc",
                "abc{",
                "a{,5}",
                "(?i)[\\w.-]{0,50}?(?:yandex)[\\s'\"]{0,3}(t1\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]{86})"
            })
    void shouldBoundTheWidthOfBoundedRegexes(String regex) {
        assertThat(GitleaksRule.windowRadius(regex), is(greaterThan(0)));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "a.*",
                ".+",
                "(?s:.)+",
                "(?:ab){1,3}",
                "(?:ab)*",
                "a{0,5000}",
                "[a-z]+[a-z]+[a-z]+[a-z]+[a-z]+",
                "[\\s\\S-]{64,}?",
                "[\\S\\s]*"
            })
    void shouldNotBoundTheWidthOfUnboundedRegexes(String regex) {
        assertThat(GitleaksRule.windowRadius(regex), is(equalTo(0)));
    }

    @Test
    void shouldOnlyWindowRulesWithBoundedWidth() throws Exception {
        // Given / When
        Config config = load(BUNDLED);
        // Then
        assertThat(rule(config, "twitter-api-key").isWindowed(), is(true));
        assertThat(rule(config, "aws-access-token").isWindowed(), is(true));
        assertThat(rule(config, "yandex-access-token").isWindowed(), is(true));
        assertThat(rule(config, "curl-auth-header").isWindowed(), is(false));
        assertThat(rule(config, "kubernetes-secret-yaml").isWindowed(), is(false));
        // Matches anything until the end of the key, which is longer than the allowance.
        assertThat(rule(config, "private-key").isWindowed(), is(false));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "linkedin-client-id",
                "lob-api-key",
                "lob-pub-api-key",
                "messagebird-api-token",
                "doppler-api-token",
                "harness-api-key",
                "vault-service-token"
            })
    void shouldWindowRulesWithKeywordsWhichAreVariantsOfTheRegex(String id) throws Exception {
        // Given / When
        GitleaksRule rule = rule(load(BUNDLED), id);
        // Then
        assertThat(rule.isWindowed(), is(true));
    }

    @ParameterizedTest
    @ValueSource(strings = {"airtable-personnal-access-token", "facebook-access-token"})
    void shouldNotWindowRulesWithKeywordsWhichAreNotInTheRegex(String id) throws Exception {
        // Given / When
        GitleaksRule rule = rule(load(BUNDLED), id);
        // Then: the keywords are the context of the token, which is not in the match.
        assertThat(rule.isWindowed(), is(false));
    }

    @ParameterizedTest
    @CsvSource({"0", "1000", "2999000", "2999984", "5999000"})
    void shouldFindSecretInLargeBodyWhenWindowed(int position) throws Exception {
        // Given
        GitleaksRule rule = rule(load(FIXTURE), "test-token");
        StringBuilder sb = new StringBuilder("x ".repeat(3_000_000));
        sb.replace(position, position + SECRET.length() + 1, SECRET + " ");
        String body = sb.toString();
        // When
        Optional<Finding> finding = rule.find(body, body.toLowerCase(), NO_ALLOWLIST, null);
        // Then
        assertThat(rule.isWindowed(), is(true));
        assertThat(finding.isPresent(), is(true));
        assertThat(finding.get().match(), is(equalTo(SECRET)));
    }

    @ParameterizedTest
    @CsvSource({"500, true", "1000, true", "5000, false"})
    void shouldOnlyFindUnboundedRunsWhichFitTheWindow(int length, boolean found) throws Exception {
        // Given: the window is limited, a longer run is cut and not reported, see windowRadius.
        GitleaksRule rule = rule(load(FIXTURE), "test-unbounded");
        String token = "unb_" + "a1b2c3d4e5".repeat(length / 10);
        String body = "x ".repeat(1_000_000) + token + " " + "x ".repeat(1_000_000);
        // When
        Optional<Finding> finding = rule.find(body, body.toLowerCase(), NO_ALLOWLIST, null);
        // Then
        assertThat(rule.isWindowed(), is(true));
        assertThat(finding.isPresent(), is(found));
    }

    @Test
    void shouldNotFindAnythingInLargeBodyWithoutKeyword() throws Exception {
        // Given
        GitleaksRule rule = rule(load(FIXTURE), "test-token");
        String body = "x ".repeat(3_000_000);
        // When
        Optional<Finding> finding = rule.find(body, body, NO_ALLOWLIST, null);
        // Then
        assertThat(finding.isPresent(), is(false));
    }
}
