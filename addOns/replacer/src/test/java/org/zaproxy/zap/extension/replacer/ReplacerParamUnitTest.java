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

    /**
     * Verifies that a rule with a method parameter is correctly written to configuration. This
     * ensures that the method field is properly persisted in the configuration, including both
     * non-empty and empty method values.
     */
    @ParameterizedTest
    @ValueSource(strings = {"POST", ""})
    void shouldWriteMethodToConfiguration(String method) {
        // Given
        param.load(configuration);
        ReplacerParamRule rule =
                new ReplacerParamRule(
                        "Test Rule",
                        "https://example.com",
                        MatchType.REQ_HEADER_STR,
                        "matchString",
                        false,
                        "replacement",
                        null,
                        true,
                        false,
                        method);

        // When
        param.addRule(rule);

        // Then
        String savedMethod =
                configuration.getString(
                        ReplacerParam.ALL_RULES_KEY + "(6)." + ReplacerParam.RULE_METHOD_KEY);
        assertThat(savedMethod, is(equalTo(method)));
    }

    /**
     * Verifies that loading a configuration without the method field (legacy config) defaults to
     * empty string. This ensures backward compatibility when loading old configurations.
     */
    @Test
    void shouldDefaultMethodToEmptyWhenLoadingLegacyConfig() {
        // Given
        ZapXmlConfiguration legacyConfig = new ZapXmlConfiguration();
        String elementBaseKey = ReplacerParam.ALL_RULES_KEY + "(0).";
        legacyConfig.setProperty(
                elementBaseKey + ReplacerParam.RULE_DESCRIPTION_KEY, "Legacy Rule");
        legacyConfig.setProperty(elementBaseKey + ReplacerParam.RULE_URL_KEY, "");
        legacyConfig.setProperty(elementBaseKey + ReplacerParam.RULE_ENABLED_KEY, Boolean.TRUE);
        legacyConfig.setProperty(
                elementBaseKey + ReplacerParam.RULE_MATCH_TYPE_KEY,
                MatchType.REQ_HEADER_STR.name());
        legacyConfig.setProperty(
                elementBaseKey + ReplacerParam.RULE_MATCH_STRING_KEY, "matchString");
        legacyConfig.setProperty(elementBaseKey + ReplacerParam.RULE_REGEX_KEY, Boolean.FALSE);
        legacyConfig.setProperty(
                elementBaseKey + ReplacerParam.RULE_REPLACEMENT_KEY, "replacement");
        legacyConfig.setProperty(elementBaseKey + ReplacerParam.RULE_INITIATORS_KEY, "");
        legacyConfig.setProperty(
                elementBaseKey + ReplacerParam.RULE_EXTRA_PROCESSING_KEY, Boolean.FALSE);
        // Intentionally NOT setting RULE_METHOD_KEY to simulate legacy config

        // When
        ReplacerParam legacyParam = new ReplacerParam();
        legacyParam.load(legacyConfig);

        // Then
        ReplacerParamRule loadedRule = legacyParam.getRule("Legacy Rule");
        assertNotNull(loadedRule);
        assertThat(loadedRule.getMethod(), is(equalTo("")));
        assertThat(loadedRule.getDescription(), is(equalTo("Legacy Rule")));
    }

    /**
     * Verifies that multiple rules with different methods are correctly written to configuration.
     * This tests that the method field is stored independently for each rule.
     */
    @Test
    void shouldWriteMultipleMethodsToConfiguration() {
        // Given
        param.load(configuration);
        ReplacerParamRule rule1 =
                new ReplacerParamRule(
                        "Rule 1",
                        "",
                        MatchType.REQ_HEADER_STR,
                        "match1",
                        false,
                        "replace1",
                        null,
                        true,
                        false,
                        "GET");
        ReplacerParamRule rule2 =
                new ReplacerParamRule(
                        "Rule 2",
                        "",
                        MatchType.REQ_HEADER_STR,
                        "match2",
                        false,
                        "replace2",
                        null,
                        true,
                        false,
                        "POST");
        ReplacerParamRule rule3 =
                new ReplacerParamRule(
                        "Rule 3",
                        "",
                        MatchType.REQ_HEADER_STR,
                        "match3",
                        false,
                        "replace3",
                        null,
                        true,
                        false,
                        "");

        // When
        param.addRule(rule1);
        param.addRule(rule2);
        param.addRule(rule3);

        // Then
        String savedMethod1 =
                configuration.getString(
                        ReplacerParam.ALL_RULES_KEY + "(6)." + ReplacerParam.RULE_METHOD_KEY);
        String savedMethod2 =
                configuration.getString(
                        ReplacerParam.ALL_RULES_KEY + "(7)." + ReplacerParam.RULE_METHOD_KEY);
        String savedMethod3 =
                configuration.getString(
                        ReplacerParam.ALL_RULES_KEY + "(8)." + ReplacerParam.RULE_METHOD_KEY);
        assertThat(savedMethod1, is(equalTo("GET")));
        assertThat(savedMethod2, is(equalTo("POST")));
        assertThat(savedMethod3, is(equalTo("")));
    }
}
