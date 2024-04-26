/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.apache.commons.configuration.HierarchicalConfiguration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.zaproxy.zap.extension.replacer.ReplacerParamRule.MatchType;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link ReplacerParam}. */
class ReplacerParamUnitTest {

    private static final int EXPECTED_V1_RULE_COUNT = 6;

    private ReplacerParam param;
    private ZapXmlConfiguration configuration;

    @BeforeEach
    void setUp() {
        param = new ReplacerParam();
        configuration = new ZapXmlConfiguration();
    }

    @Test
    void shouldHaveConfigVersionKey() {
        // Given / When
        param.load(configuration);
        // Then
        assertThat(param.getConfigVersionKey(), is(equalTo("replacer[@version]")));
    }

    @ParameterizedTest
    @ValueSource(strings = {"true", "false"})
    void shouldLoadConfirmRemoveFromConfig(boolean state) {
        // Given
        configuration.setProperty("replacer.confirmRemoveToken", state);
        // When
        param.load(configuration);
        // Then
        assertThat(param.isConfirmRemoveToken(), is(equalTo(state)));
    }

    @Test
    void shouldDefaultConfirmRemoveTrue() {
        // Given / When
        param.load(configuration);
        // Then
        assertThat(param.isConfirmRemoveToken(), is(equalTo(true)));
    }

    @Test
    void shouldHaveExpectedVersionInDefaultConfig() {
        // Given / When
        param.load(configuration);
        // Then
        assertThat(param.getCurrentVersion(), is(equalTo(1)));
    }

    @Test
    void shouldHaveExpectedRulesOnUpdateFromUnversioned() {
        // Given
        List<String> expectedDescs =
                List.of(
                        "Remove CSP",
                        "Remove HSTS",
                        "Replace User-Agent with shellshock attack",
                        ReplacerParam.REPORT_TO_DESC);
        // When
        param.load(configuration);
        // Then
        assertThat(param.getRules().size(), is(equalTo(EXPECTED_V1_RULE_COUNT)));

        List<String> ruleDescs = new ArrayList<>();
        param.getRules().forEach(x -> ruleDescs.add(x.getDescription()));

        assertTrue(ruleDescs.containsAll(expectedDescs));
    }

    @ParameterizedTest
    @CsvSource(
            value = {"2, 2, 1", "999, 2, 1", "null, 4, 3"},
            nullValues = {"null"})
    void shouldNotOverwriteExistingRulesOnUpdate(Object version, int count, int index) {
        // Given / When
        param.load(configuration);
        configuration = new ZapXmlConfiguration();
        configuration.setProperty(param.getConfigVersionKey(), version);
        createConfigWithReportToRule(configuration);
        param.load(configuration);
        ReplacerParamRule enabledReportTo = getReportToRule(true);
        param.addRule(enabledReportTo);
        // Then
        assertThat(param.getRules().size(), is(equalTo(count)));
        // getRule returns first match (0th)
        ReplacerParamRule originalRule = param.getRule(ReplacerParam.REPORT_TO_DESC);
        assertNotNull(originalRule);
        assertThat(originalRule.getDescription(), is(equalTo(ReplacerParam.REPORT_TO_DESC)));
        assertThat(originalRule.isEnabled(), is(equalTo(false)));
        // The nth rule should be the added enabled one
        assertThat(param.getRules().get(index).isEnabled(), is(equalTo(true)));
    }

    private void createConfigWithReportToRule(ZapXmlConfiguration config) {
        ((HierarchicalConfiguration) config).clearTree(ReplacerParam.ALL_RULES_KEY);
        List<ReplacerParamRule> rules = List.of(getReportToRule(false));
        ArrayList<String> enabledTokens = new ArrayList<>(rules.size());
        for (int i = 0, size = rules.size(); i < size; ++i) {
            String elementBaseKey = ReplacerParam.ALL_RULES_KEY + "(" + i + ").";
            ReplacerParamRule rule = rules.get(i);

            config.setProperty(
                    elementBaseKey + ReplacerParam.RULE_DESCRIPTION_KEY, rule.getDescription());
            config.setProperty(elementBaseKey + ReplacerParam.RULE_URL_KEY, rule.getUrl());
            config.setProperty(
                    elementBaseKey + ReplacerParam.RULE_ENABLED_KEY,
                    Boolean.valueOf(rule.isEnabled()));
            config.setProperty(
                    elementBaseKey + ReplacerParam.RULE_MATCH_TYPE_KEY, rule.getMatchType().name());
            config.setProperty(
                    elementBaseKey + ReplacerParam.RULE_MATCH_STRING_KEY, rule.getMatchString());
            config.setProperty(
                    elementBaseKey + ReplacerParam.RULE_REGEX_KEY,
                    Boolean.valueOf(rule.isMatchRegex()));
            config.setProperty(
                    elementBaseKey + ReplacerParam.RULE_REPLACEMENT_KEY, rule.getReplacement());
            config.setProperty(
                    elementBaseKey + ReplacerParam.RULE_EXTRA_PROCESSING_KEY,
                    Boolean.valueOf(rule.isTokenProcessingEnabled()));

            List<Integer> initiators = rule.getInitiators();
            if (initiators == null || initiators.isEmpty()) {
                config.setProperty(elementBaseKey + ReplacerParam.RULE_INITIATORS_KEY, "");
            } else {
                config.setProperty(
                        elementBaseKey + ReplacerParam.RULE_INITIATORS_KEY, initiators.toString());
            }

            if (rule.isEnabled()) {
                enabledTokens.add(rule.getDescription());
            }
        }

        enabledTokens.trimToSize();
    }

    private ReplacerParamRule getReportToRule(boolean enabled) {
        return new ReplacerParamRule(
                ReplacerParam.REPORT_TO_DESC,
                MatchType.RESP_HEADER_STR,
                ReplacerParam.REPORT_TO_REGEX,
                true,
                ReplacerParam.REPORT_TO_REPLACEMENT,
                null,
                enabled);
    }
}
