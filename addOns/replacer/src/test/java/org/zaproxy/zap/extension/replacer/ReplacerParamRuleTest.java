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
import static org.zaproxy.zap.extension.replacer.ReplacerParamRule.MatchType.REQ_HEADER_STR;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

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

    /**
     * Verifies that the method field is correctly initialized when creating a rule with all
     * parameters including the method parameter. This ensures the method is stored properly in the
     * rule.
     */
    @Test
    void shouldInitializeMethodWhenCreatingRuleWithMethod() {
        // Given / When
        ReplacerParamRule rule =
                new ReplacerParamRule(
                        "Test Rule",
                        "https://example.com",
                        REQ_HEADER_STR,
                        "matchString",
                        true,
                        "replacement",
                        null,
                        true,
                        false,
                        "POST");

        // Then
        assertThat(rule.getMethod(), equalTo("POST"));
    }

    /**
     * Verifies that the method field defaults to empty string when creating a rule without
     * specifying the method parameter. This ensures backward compatibility with existing code.
     */
    @Test
    void shouldDefaultMethodToEmptyStringWhenNotSpecified() {
        // Given / When
        ReplacerParamRule rule =
                new ReplacerParamRule(
                        "Test Rule",
                        REQ_HEADER_STR,
                        "matchString",
                        true,
                        "replacement",
                        null,
                        true);

        // Then
        assertThat(rule.getMethod(), equalTo(""));
    }

    /**
     * Verifies that copying a rule preserves the method field. This tests the copy constructor to
     * ensure all fields, including method, are properly duplicated.
     */
    @Test
    void shouldCopyMethodWhenCloningRule() {
        // Given
        ReplacerParamRule original =
                new ReplacerParamRule(
                        "Test Rule",
                        "https://example.com",
                        REQ_HEADER_STR,
                        "matchString",
                        true,
                        "replacement",
                        null,
                        true,
                        false,
                        "DELETE");

        // When
        ReplacerParamRule copy = new ReplacerParamRule(original);

        // Then
        assertThat(copy.getMethod(), equalTo("DELETE"));
    }

    /**
     * Verifies that the equals method correctly compares rules with different method values. This
     * ensures that the method field is included in equality checks.
     */
    @Test
    void shouldConsiderMethodInEquality() {
        // Given
        ReplacerParamRule rule1 =
                new ReplacerParamRule(
                        "Test Rule",
                        "",
                        REQ_HEADER_STR,
                        "matchString",
                        false,
                        "replacement",
                        null,
                        true,
                        false,
                        "GET");

        ReplacerParamRule rule2 =
                new ReplacerParamRule(
                        "Test Rule",
                        "",
                        REQ_HEADER_STR,
                        "matchString",
                        false,
                        "replacement",
                        null,
                        true,
                        false,
                        "POST");

        // When / Then
        assertThat(rule1.equals(rule2), equalTo(false));
    }

    /**
     * Verifies that the hashCode method includes the method field in its calculation. This ensures
     * that rules with different methods produce different hash codes.
     */
    @Test
    void shouldIncludeMethodInHashCode() {
        // Given
        ReplacerParamRule rule1 =
                new ReplacerParamRule(
                        "Test Rule",
                        "",
                        REQ_HEADER_STR,
                        "matchString",
                        false,
                        "replacement",
                        null,
                        true,
                        false,
                        "GET");

        ReplacerParamRule rule2 =
                new ReplacerParamRule(
                        "Test Rule",
                        "",
                        REQ_HEADER_STR,
                        "matchString",
                        false,
                        "replacement",
                        null,
                        true,
                        false,
                        "POST");

        // When / Then
        assertThat(rule1.hashCode() == rule2.hashCode(), equalTo(false));
    }

    /**
     * Verifies that passing null for the method parameter in the constructor does not throw an
     * exception and defaults to empty string.
     */
    @Test
    void shouldHandleNullMethodInConstructor() {
        // Given / When
        ReplacerParamRule rule =
                new ReplacerParamRule(
                        "Test Rule",
                        "",
                        REQ_HEADER_STR,
                        "matchString",
                        false,
                        "replacement",
                        null,
                        true,
                        false,
                        null);

        // Then
        assertThat(rule.getMethod(), equalTo(""));
    }

    /**
     * Verifies that passing null to setMethod does not throw an exception and sets the method to
     * empty string.
     */
    @Test
    void shouldHandleNullMethodInSetter() {
        // Given
        ReplacerParamRule rule =
                new ReplacerParamRule(
                        "Test Rule",
                        "",
                        REQ_HEADER_STR,
                        "matchString",
                        false,
                        "replacement",
                        null,
                        true,
                        false,
                        "GET");

        // When
        rule.setMethod(null);

        // Then
        assertThat(rule.getMethod(), equalTo(""));
    }

    /** Verifies that passing an empty string to setMethod works correctly. */
    @Test
    void shouldHandleEmptyMethodInSetter() {
        // Given
        ReplacerParamRule rule =
                new ReplacerParamRule(
                        "Test Rule",
                        "",
                        REQ_HEADER_STR,
                        "matchString",
                        false,
                        "replacement",
                        null,
                        true,
                        false,
                        "GET");

        // When
        rule.setMethod("");

        // Then
        assertThat(rule.getMethod(), equalTo(""));
    }
}
