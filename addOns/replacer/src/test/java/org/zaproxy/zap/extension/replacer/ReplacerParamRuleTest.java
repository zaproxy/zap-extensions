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
package org.zaproxy.zap.extension.replacer;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.zaproxy.zap.extension.replacer.ReplacerParamRule.MatchType.REQ_HEADER_STR;

import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.zaproxy.zap.extension.replacer.ReplacerParamRule.MatchType;

class ReplacerParamRuleTest {

    @Test
    void shouldSubstituteHexValuesInReplacementString() {
        // Given
        String replacement = "abc\\x01\\xaadef";

        // When
        ReplacerParamRule hexValueRegexRule =
                new ReplacerParamRule(
                        "", REQ_HEADER_STR, "anyMatchString", true, replacement, null, true);

        // Then
        assertThat(
                hexValueRegexRule.getEscapedReplacement(),
                equalTo(
                        new String(
                                new byte[] {'a', 'b', 'c', 1, (byte) 170, 'd', 'e', 'f'},
                                StandardCharsets.US_ASCII)));
    }

    @Test
    void shouldSubstituteHexValuesInReplacementStringForNonRegexMatch() {
        // Given
        String replacement = "abc\\x01\\xaadef";

        // When
        ReplacerParamRule hexValueRegexRule =
                new ReplacerParamRule(
                        "", REQ_HEADER_STR, "anyMatchString", false, replacement, null, true);

        // Then
        assertThat(
                hexValueRegexRule.getEscapedReplacement(),
                equalTo(
                        new String(
                                new byte[] {'a', 'b', 'c', 1, (byte) 170, 'd', 'e', 'f'},
                                StandardCharsets.US_ASCII)));
    }

    @Test
    void shouldNotSubstituteHexValuesInReplacementStringGivenBackslashIsEscaped() {
        // Given
        String replacement = "abc\\\\x01\\\\xaadef";

        // When
        ReplacerParamRule hexValueRegexRule =
                new ReplacerParamRule(
                        "", REQ_HEADER_STR, "anyMatchString", true, replacement, null, true);

        // Then
        assertThat(hexValueRegexRule.getEscapedReplacement(), equalTo("abc\\x01\\xaadef"));
    }

    @Test
    void shouldNotSubstituteGivenHexValueIsNotHexadecimal() {
        // Given
        String replacement = "\\xZZ";

        // When
        ReplacerParamRule hexValueRegexRule =
                new ReplacerParamRule(
                        "", REQ_HEADER_STR, "anyMatchString", true, replacement, null, true);

        // Then
        assertThat(hexValueRegexRule.getEscapedReplacement(), equalTo("\\xZZ"));
    }

    @Test
    void shouldNotSubstituteGivenThereIsOnlyOneBackSlash() {
        // Given
        String replacement = "\\";

        // When
        ReplacerParamRule hexValueRegexRule =
                new ReplacerParamRule(
                        "", REQ_HEADER_STR, "anyMatchString", true, replacement, null, true);

        // Then
        assertThat(hexValueRegexRule.getEscapedReplacement(), equalTo("\\"));
    }

    @Test
    void shouldNotSubstituteGivenThereIsOnlyBeginningOfHexValue() {
        // Given
        String replacement = "\\x";

        // When
        ReplacerParamRule hexValueRegexRule =
                new ReplacerParamRule(
                        "", REQ_HEADER_STR, "anyMatchString", true, replacement, null, true);

        // Then
        assertThat(hexValueRegexRule.getEscapedReplacement(), equalTo("\\x"));
    }

    @Test
    void shouldConstructRule() {
        // Given / When
        ReplacerParamRule rule =
                new ReplacerParamRule(
                        "Description",
                        "Url",
                        MatchType.REQ_BODY_STR,
                        "MatchString",
                        false,
                        "Replacement",
                        List.of(1, 2),
                        false,
                        true,
                        "Method");

        // Then
        assertThat(rule.getDescription(), is(equalTo("Description")));
        assertThat(rule.getUrl(), is(equalTo("Url")));
        assertThat(rule.getMatchType(), is(equalTo(MatchType.REQ_BODY_STR)));
        assertThat(rule.getMatchString(), is(equalTo("MatchString")));
        assertThat(rule.isMatchRegex(), is(equalTo(false)));
        assertThat(rule.getReplacement(), is(equalTo("Replacement")));
        assertThat(rule.getInitiators(), is(equalTo(List.of(1, 2))));
        assertThat(rule.isEnabled(), is(equalTo(false)));
        assertThat(rule.isTokenProcessingEnabled(), is(equalTo(true)));
        assertThat(rule.getMethod(), is(equalTo("Method")));
    }

    @Test
    void shouldConstructRuleFromRule() {
        // Given
        ReplacerParamRule rule =
                new ReplacerParamRule(
                        "Description",
                        "Url",
                        MatchType.REQ_BODY_STR,
                        "MatchString",
                        false,
                        "Replacement",
                        List.of(1, 2),
                        false,
                        true,
                        "Method");

        // When
        ReplacerParamRule copy = new ReplacerParamRule(rule);

        // Then
        assertThat(copy.getDescription(), is(equalTo("Description")));
        assertThat(copy.getUrl(), is(equalTo("Url")));
        assertThat(copy.getMatchType(), is(equalTo(MatchType.REQ_BODY_STR)));
        assertThat(copy.getMatchString(), is(equalTo("MatchString")));
        assertThat(copy.isMatchRegex(), is(equalTo(false)));
        assertThat(copy.getReplacement(), is(equalTo("Replacement")));
        assertThat(copy.getInitiators(), is(equalTo(List.of(1, 2))));
        assertThat(copy.isEnabled(), is(equalTo(false)));
        assertThat(copy.isTokenProcessingEnabled(), is(equalTo(true)));
        assertThat(copy.getMethod(), is(equalTo("Method")));
    }

    @Test
    void shouldConsiderMethodInEquality() {
        // Given
        ReplacerParamRule rule1 =
                new ReplacerParamRule(
                        "", "", REQ_HEADER_STR, "", false, "", null, true, true, "GET");

        ReplacerParamRule rule2 =
                new ReplacerParamRule(
                        "", "", REQ_HEADER_STR, "", false, "", null, true, true, "POST");

        // When / Then
        assertThat(rule1.equals(rule2), is(equalTo(false)));
    }

    @Test
    void shouldIncludeMethodInHashCode() {
        // Given
        ReplacerParamRule rule1 =
                new ReplacerParamRule(
                        "", "", REQ_HEADER_STR, "", false, "", null, true, true, "GET");

        ReplacerParamRule rule2 =
                new ReplacerParamRule(
                        "", "", REQ_HEADER_STR, "", false, "", null, true, true, "POST");

        // When / Then
        assertThat(rule1.hashCode() == rule2.hashCode(), is(equalTo(false)));
    }

    @ParameterizedTest
    @CsvSource({"GET,GET", ",''", "'',''"})
    void shouldSetMethod(String method, String expected) {
        // Given
        ReplacerParamRule rule =
                new ReplacerParamRule(
                        "", "", REQ_HEADER_STR, "", false, "", null, true, true, method);

        // When
        rule.setMethod(method);

        // Then
        assertThat(rule.getMethod(), is(equalTo(expected)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "GET", "POST"})
    void shouldMatchAnyMethodIfNoneSet(String method) {
        // Given
        ReplacerParamRule rule = new ReplacerParamRule();
        // When
        boolean matches = rule.matchesMethod(method);
        // Then
        assertThat(matches, equalTo(true));
    }

    @ParameterizedTest
    @CsvSource({"GET,GET,true", "GET,get,true", "GET,POST,false"})
    void shouldMatchMethodSet(String ruleMethod, String requestMethod, boolean expectedMatch) {
        // Given
        ReplacerParamRule rule = new ReplacerParamRule();
        rule.setMethod(ruleMethod);
        // When
        boolean matches = rule.matchesMethod(requestMethod);
        // Then
        assertThat(matches, equalTo(expectedMatch));
    }
}
