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
package org.zaproxy.addon.commonlib.gspm.internal;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.ResourceBundle;
import net.sf.json.JSONObject;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.zaproxy.addon.commonlib.ExtensionCommonlib;
import org.zaproxy.addon.commonlib.gspm.GspmCategory;
import org.zaproxy.addon.commonlib.gspm.GspmPhase;
import org.zaproxy.addon.commonlib.gspm.GspmPolicy;
import org.zaproxy.addon.commonlib.gspm.GspmRegistry;
import org.zaproxy.addon.commonlib.gspm.GspmRule;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.extension.api.ApiView;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.I18N;

/** Unit test for {@link GlobalScanPolicyApi}. */
class GlobalScanPolicyApiUnitTest extends TestUtils {

    private static final String POLICY = "P";
    private static final int INJECTION_RULE = 100;
    private static final int INJECTION_RULE_2 = 101;
    private static final int SERVER_RULE = 200;

    @TempDir static java.nio.file.Path zapHomeDir;

    private static String zapHome;

    @BeforeAll
    static void setup() {
        mockMessages(new ExtensionCommonlib());
        zapHome = Constant.getZapHome();
        Constant.setZapHome(zapHomeDir.toString());
    }

    @AfterAll
    static void cleanUp() {
        Constant.messages = null;
        if (zapHome != null) {
            Constant.setZapHome(zapHome);
        }
    }

    private GspmRegistry registry;
    private GlobalScanPolicyApi api;

    @BeforeEach
    void setUp() throws Exception {
        Files.createDirectories(Constant.getPoliciesDir().toPath());
        registry = new GspmRegistry();
        registry.registerRule(rule(INJECTION_RULE, Category.INJECTION));
        registry.registerRule(rule(INJECTION_RULE_2, Category.INJECTION));
        registry.registerRule(rule(SERVER_RULE, Category.SERVER));
        GspmPolicyOperations.addPolicy(
                registry, POLICY, "ascan", AlertThreshold.LOW, AttackStrength.MEDIUM);
        api = new GlobalScanPolicyApi(registry);
    }

    @Test
    void shouldHavePrefix() {
        assertThat(api.getPrefix(), is(equalTo("globalScanPolicy")));
    }

    @Test
    void shouldHaveDescriptionsForAllEndpointsAndParameters() {
        // Given
        I18N mockedMessages = Constant.messages;
        // The real one, as it finds the messages by the prefix of the key, like the API UI does.
        Constant.messages = new I18N(Locale.ENGLISH);
        Constant.messages.addMessageBundle(
                new ExtensionCommonlib().getI18nPrefix(),
                ResourceBundle.getBundle(
                        "org.zaproxy.addon.commonlib.resources.Messages", Locale.ENGLISH));
        try {
            // When
            List<String> missing = new ArrayList<>();
            addIfMissing(missing, api.getDescriptionKey());
            for (ApiView view : api.getApiViews()) {
                addIfMissing(missing, view.getDescriptionTag());
                view.getParameters().forEach(p -> addIfMissing(missing, p.getDescriptionKey()));
            }
            for (ApiAction action : api.getApiActions()) {
                addIfMissing(missing, action.getDescriptionTag());
                action.getParameters().forEach(p -> addIfMissing(missing, p.getDescriptionKey()));
            }
            // Then
            assertThat(missing, is(empty()));
        } finally {
            Constant.messages = mockedMessages;
        }
    }

    private static void addIfMissing(List<String> missing, String key) {
        if (!Constant.messages.containsKey(key)) {
            missing.add(key);
        }
    }

    @Test
    void shouldListPolicyNames() throws Exception {
        // When
        ApiResponse response = api.handleApiView("policyNames", new JSONObject());
        // Then
        assertThat(response.toJSON().toString(), containsString(POLICY));
    }

    @Test
    void shouldAddPolicy() throws Exception {
        // When
        ApiResponse response =
                api.handleApiAction(
                        "addPolicy",
                        params(
                                "policyName",
                                "New",
                                "alertThreshold",
                                "High",
                                "attackStrength",
                                "Low"));
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        assertThat(
                GspmPolicyOperations.getDefaultThreshold(registry, "New", "ascan"),
                is(equalTo(AlertThreshold.HIGH)));
        assertThat(
                GspmPolicyOperations.getDefaultStrength(registry, "New", "ascan"),
                is(equalTo(AttackStrength.LOW)));
    }

    @Test
    void shouldFailToAddExistingOrIllegalPolicy() {
        assertType(ApiException.Type.ALREADY_EXISTS, "addPolicy", params("policyName", POLICY));
        assertType(ApiException.Type.ILLEGAL_PARAMETER, "addPolicy", params("policyName", "a/b"));
        assertType(
                ApiException.Type.ILLEGAL_PARAMETER,
                "addPolicy",
                params("policyName", "New", "alertThreshold", "Default"));
        assertType(
                ApiException.Type.ILLEGAL_PARAMETER,
                "addPolicy",
                params("policyName", "New", "attackStrength", "Default"));
        assertType(
                ApiException.Type.DOES_NOT_EXIST,
                "addPolicy",
                params("policyName", "New", "alertThreshold", "Unknown"));
    }

    @Test
    void shouldFailWithMissingPolicyNameOrPath() {
        assertType(ApiException.Type.MISSING_PARAMETER, "addPolicy", params());
        assertType(ApiException.Type.MISSING_PARAMETER, "importLegacyPolicy", params());
    }

    @Test
    void shouldUpdatePolicy() throws Exception {
        // When
        api.handleApiAction(
                "updatePolicy",
                params("policyName", POLICY, "tool", "ascan", "attackStrength", "high"));
        // Then
        assertThat(
                GspmPolicyOperations.getDefaultThreshold(registry, POLICY, "ascan"),
                is(equalTo(AlertThreshold.LOW)));
        assertThat(
                GspmPolicyOperations.getDefaultStrength(registry, POLICY, "ascan"),
                is(equalTo(AttackStrength.HIGH)));
    }

    @Test
    void shouldRemovePolicy() throws Exception {
        // Given
        GspmPolicyOperations.addPolicy(registry, "Other", "ascan", null, null);
        // When
        api.handleApiAction("removePolicy", params("policyName", "Other"));
        // Then
        assertThat(registry.getPolicy("Other") == null, is(true));
    }

    @Test
    void shouldNotRemoveLastBuiltInOrUnknownPolicy() {
        assertType(
                ApiException.Type.ILLEGAL_PARAMETER, "removePolicy", params("policyName", POLICY));
        registry.addPolicy(new GspmPolicy(GspmRegistry.getDefaultPolicyName()));
        assertType(
                ApiException.Type.ILLEGAL_PARAMETER,
                "removePolicy",
                params("policyName", GspmRegistry.getDefaultPolicyName()));
        assertType(ApiException.Type.DOES_NOT_EXIST, "removePolicy", params("policyName", "x"));
    }

    @Test
    void shouldFailToImportMissingOrNonFilePath() throws Exception {
        assertType(
                ApiException.Type.DOES_NOT_EXIST,
                "importLegacyPolicy",
                params("path", new File(zapHomeDir.toFile(), "missing.policy").getAbsolutePath()));
        assertType(
                ApiException.Type.ILLEGAL_PARAMETER,
                "importLegacyPolicy",
                params("path", zapHomeDir.toFile().getAbsolutePath()));
    }

    @Test
    void shouldImportLegacyPolicy() throws Exception {
        // Given
        File file = new File(zapHomeDir.toFile(), "Imported.policy");
        Files.writeString(
                file.toPath(),
                "<configuration><policy>Imported</policy><scanner><level>HIGH</level>"
                        + "<strength>LOW</strength></scanner></configuration>");
        // When
        api.handleApiAction("importLegacyPolicy", params("path", file.getAbsolutePath()));
        // Then
        assertThat(registry.getPolicy("Imported") != null, is(true));
        assertThat(
                GspmPolicyOperations.getDefaultThreshold(registry, "Imported", "ascan"),
                is(equalTo(AlertThreshold.HIGH)));
        // When / Then
        assertType(
                ApiException.Type.ALREADY_EXISTS,
                "importLegacyPolicy",
                params("path", file.getAbsolutePath()));
    }

    @Test
    void shouldFailToImportInvalidLegacyPolicy() throws Exception {
        // Given
        File file = new File(zapHomeDir.toFile(), "Invalid.policy");
        Files.writeString(file.toPath(), "not xml");
        // When / Then
        assertType(
                ApiException.Type.BAD_EXTERNAL_DATA,
                "importLegacyPolicy",
                params("path", file.getAbsolutePath()));
    }

    @Test
    void shouldDisableAndEnableAllActiveScanRules() throws Exception {
        // When
        api.handleApiAction("disableAllRules", params("policyName", POLICY, "tool", "ascan"));
        // Then
        assertThat(threshold(SERVER_RULE), is(equalTo(AlertThreshold.OFF)));
        assertThat(threshold(INJECTION_RULE), is(equalTo(AlertThreshold.OFF)));
        // When
        api.handleApiAction("enableAllRules", params("policyName", POLICY, "tool", "ascan"));
        // Then
        assertThat(threshold(SERVER_RULE), is(equalTo(AlertThreshold.LOW)));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldEnableAndDisableGivenActiveScanRules(boolean enable) throws Exception {
        // Given
        if (enable) {
            api.handleApiAction("disableAllRules", params("policyName", POLICY, "tool", "ascan"));
        }
        // When
        api.handleApiAction(
                enable ? "enableRules" : "disableRules",
                params("policyName", POLICY, "ruleIds", "100, 200"));
        // Then
        AlertThreshold expected = enable ? AlertThreshold.LOW : AlertThreshold.OFF;
        assertThat(threshold(INJECTION_RULE), is(equalTo(expected)));
        assertThat(threshold(SERVER_RULE), is(equalTo(expected)));
        assertThat(
                threshold(INJECTION_RULE_2),
                is(equalTo(enable ? AlertThreshold.OFF : AlertThreshold.LOW)));
    }

    @Test
    void shouldApplyValidRulesBeforeFailingWithInvalidOrUnknownRules() throws Exception {
        // When
        ApiException unknown =
                assertThrows(
                        ApiException.class,
                        () ->
                                api.handleApiAction(
                                        "disableRules",
                                        params("policyName", POLICY, "ruleIds", "100, 999")));
        // Then
        assertThat(unknown.getType(), is(equalTo(ApiException.Type.DOES_NOT_EXIST)));
        assertThat(threshold(INJECTION_RULE), is(equalTo(AlertThreshold.OFF)));
        // When
        ApiException invalid =
                assertThrows(
                        ApiException.class,
                        () ->
                                api.handleApiAction(
                                        "disableRules",
                                        params("policyName", POLICY, "ruleIds", "200, a, 101")));
        // Then
        assertThat(invalid.getType(), is(equalTo(ApiException.Type.ILLEGAL_PARAMETER)));
        assertThat(threshold(SERVER_RULE), is(equalTo(AlertThreshold.OFF)));
        assertThat(threshold(INJECTION_RULE_2), is(equalTo(AlertThreshold.LOW)));
    }

    @Test
    void shouldSetEnabledCategories() throws Exception {
        // When
        api.handleApiAction(
                "setEnabledCategories",
                params("policyName", POLICY, "tool", "ascan", "categoryKeys", "server"));
        // Then
        assertThat(threshold(SERVER_RULE), is(equalTo(AlertThreshold.LOW)));
        assertThat(threshold(INJECTION_RULE), is(equalTo(AlertThreshold.OFF)));
        // When / Then
        assertType(
                ApiException.Type.ILLEGAL_PARAMETER,
                "setEnabledCategories",
                params("policyName", POLICY, "tool", "ascan", "categoryKeys", " "));
        assertType(
                ApiException.Type.DOES_NOT_EXIST,
                "setEnabledCategories",
                params("policyName", POLICY, "tool", "ascan", "categoryKeys", "unknown"));
        assertType(
                ApiException.Type.MISSING_PARAMETER,
                "setEnabledCategories",
                params("policyName", POLICY, "categoryKeys", "server"));
    }

    @Test
    void shouldSetCategoryThresholdAndStrength() throws Exception {
        // When
        api.handleApiAction(
                "setCategoryThreshold",
                params(
                        "policyName",
                        POLICY,
                        "tool",
                        "ascan",
                        "categoryKey",
                        "inject",
                        "alertThreshold",
                        "High"));
        api.handleApiAction(
                "setCategoryStrength",
                params(
                        "policyName",
                        POLICY,
                        "tool",
                        "ascan",
                        "categoryKey",
                        "inject",
                        "attackStrength",
                        "Insane"));
        // Then
        assertThat(threshold(INJECTION_RULE), is(equalTo(AlertThreshold.HIGH)));
        assertThat(threshold(SERVER_RULE), is(equalTo(AlertThreshold.LOW)));
        assertThat(strength(INJECTION_RULE_2), is(equalTo(AttackStrength.INSANE)));
        // When / Then
        assertType(
                ApiException.Type.ILLEGAL_PARAMETER,
                "setCategoryThreshold",
                params(
                        "policyName",
                        POLICY,
                        "tool",
                        "ascan",
                        "categoryKey",
                        "",
                        "alertThreshold",
                        "High"));
        assertType(
                ApiException.Type.DOES_NOT_EXIST,
                "setCategoryStrength",
                params(
                        "policyName",
                        POLICY,
                        "tool",
                        "ascan",
                        "categoryKey",
                        "unknown",
                        "attackStrength",
                        "High"));
    }

    @Test
    void shouldParseThresholdAndStrengthIndependentlyOfDefaultLocale() throws Exception {
        // Given
        Locale defaultLocale = Locale.getDefault();
        // In Turkish "i" is uppercased to "\u0130", which would not match the values.
        Locale.setDefault(Locale.forLanguageTag("tr-TR"));
        try {
            // When
            api.handleApiAction(
                    "setRuleThreshold",
                    params("policyName", POLICY, "ruleId", "200", "alertThreshold", "high"));
            api.handleApiAction(
                    "setRuleStrength",
                    params("policyName", POLICY, "ruleId", "200", "attackStrength", "medium"));
            // Then
            assertThat(threshold(SERVER_RULE), is(equalTo(AlertThreshold.HIGH)));
            assertThat(strength(SERVER_RULE), is(equalTo(AttackStrength.MEDIUM)));
        } finally {
            Locale.setDefault(defaultLocale);
        }
    }

    @Test
    void shouldSetRuleThresholdAndStrength() throws Exception {
        // When
        api.handleApiAction(
                "setRuleThreshold",
                params("policyName", POLICY, "ruleId", "200", "alertThreshold", "off"));
        api.handleApiAction(
                "setRuleStrength",
                params("policyName", POLICY, "ruleId", "200", "attackStrength", "high"));
        // Then
        assertThat(threshold(SERVER_RULE), is(equalTo(AlertThreshold.OFF)));
        assertThat(strength(SERVER_RULE), is(equalTo(AttackStrength.HIGH)));
        assertThat(threshold(INJECTION_RULE), is(equalTo(AlertThreshold.LOW)));
    }

    @Test
    void shouldRestrictRulesToToolIfSpecified() throws Exception {
        // Given
        registry.registerRule(otherToolRule(300));
        // When
        api.handleApiAction(
                "setRuleThreshold",
                params("policyName", POLICY, "ruleId", "300", "alertThreshold", "high"));
        // Then
        assertThat(threshold(300), is(equalTo(AlertThreshold.HIGH)));
        assertType(
                ApiException.Type.DOES_NOT_EXIST,
                "setRuleThreshold",
                params(
                        "policyName",
                        POLICY,
                        "ruleId",
                        "300",
                        "alertThreshold",
                        "high",
                        "tool",
                        "ascan"));
        assertType(
                ApiException.Type.DOES_NOT_EXIST,
                "disableRules",
                params("policyName", POLICY, "ruleIds", "100", "tool", "pscan"));
    }

    @Test
    void shouldOnlyChangeRulesOfToolWhenEnablingAndDisablingAll() throws Exception {
        // Given
        registry.registerRule(otherToolRule(300));
        // When
        api.handleApiAction("disableAllRules", params("policyName", POLICY, "tool", "ascan"));
        // Then
        assertThat(threshold(INJECTION_RULE), is(equalTo(AlertThreshold.OFF)));
        assertThat(threshold(300), is(equalTo(AlertThreshold.MEDIUM)));
        assertType(
                ApiException.Type.MISSING_PARAMETER,
                "disableAllRules",
                params("policyName", POLICY));
        assertType(
                ApiException.Type.DOES_NOT_EXIST,
                "disableAllRules",
                params("policyName", POLICY, "tool", "unknown"));
    }

    @Test
    void shouldSetDefaultsOfToolOrOfAllRules() throws Exception {
        // When
        api.handleApiAction(
                "addPolicy",
                params("policyName", "ForTool", "tool", "ascan", "alertThreshold", "high"));
        api.handleApiAction("addPolicy", params("policyName", "ForAll", "alertThreshold", "high"));
        // Then
        assertThat(
                GspmPolicyOperations.getDefaultThreshold(registry, "ForTool", "ascan"),
                is(equalTo(AlertThreshold.HIGH)));
        assertThat(
                GspmPolicyOperations.getDefaultThreshold(registry, "ForTool", null) == null,
                is(true));
        assertThat(
                GspmPolicyOperations.getDefaultThreshold(registry, "ForAll", null),
                is(equalTo(AlertThreshold.HIGH)));
        assertThat(
                GspmPolicyOperations.getDefaultThreshold(registry, "ForAll", "ascan"),
                is(equalTo(AlertThreshold.HIGH)));
        // When
        api.handleApiAction(
                "updatePolicy",
                params("policyName", "ForTool", "tool", "ascan", "attackStrength", "low"));
        // Then
        assertThat(
                GspmPolicyOperations.getDefaultStrength(registry, "ForTool", "ascan"),
                is(equalTo(AttackStrength.LOW)));
    }

    @Test
    void shouldFailWithUnknownPolicyRuleOrValues() {
        assertType(
                ApiException.Type.DOES_NOT_EXIST,
                "enableAllRules",
                params("policyName", "Unknown"));
        assertType(
                ApiException.Type.DOES_NOT_EXIST,
                "setRuleThreshold",
                params("policyName", POLICY, "ruleId", "999", "alertThreshold", "off"));
        assertType(
                ApiException.Type.DOES_NOT_EXIST,
                "setRuleThreshold",
                params("policyName", POLICY, "ruleId", "100", "alertThreshold", "unknown"));
        assertType(
                ApiException.Type.DOES_NOT_EXIST,
                "setRuleStrength",
                params("policyName", POLICY, "ruleId", "100", "attackStrength", "unknown"));
        assertType(ApiException.Type.BAD_ACTION, "unknown", params());
    }

    private void assertType(ApiException.Type type, String action, JSONObject params) {
        ApiException e =
                assertThrows(ApiException.class, () -> api.handleApiAction(action, params));
        assertThat(e.getType(), is(equalTo(type)));
    }

    private AlertThreshold threshold(int ruleId) {
        return rule(ruleId).getAlertThreshold();
    }

    private AttackStrength strength(int ruleId) {
        return rule(ruleId).getAttackStrength();
    }

    private GspmRule rule(int ruleId) {
        return registry.getAllRulesForPolicy(registry.getPolicy(POLICY)).stream()
                .filter(r -> r.getId() == ruleId)
                .findFirst()
                .get();
    }

    private static JSONObject params(String... keysAndValues) {
        JSONObject params = new JSONObject();
        for (int i = 0; i < keysAndValues.length; i += 2) {
            params.put(keysAndValues[i], keysAndValues[i + 1]);
        }
        return params;
    }

    private static GspmRule rule(int id, int category) {
        return new TestRule(
                id, GspmActiveScanRegistrar.TOOL, GspmActiveScanRegistrar.categoryKey(category));
    }

    private static GspmRule otherToolRule(int id) {
        return new TestRule(id, "pscan", "server-side");
    }

    private static final class TestRule implements GspmRule {

        private final int id;
        private final String tool;
        private final String category;

        TestRule(int id, String tool, String category) {
            this.id = id;
            this.tool = tool;
            this.category = category;
        }

        @Override
        public int getId() {
            return id;
        }

        @Override
        public String getName() {
            return "Rule " + id;
        }

        @Override
        public String getTool() {
            return tool;
        }

        @Override
        public GspmPhase getPhase() {
            return GspmPhase.ACTIVE;
        }

        @Override
        public List<GspmCategory> getCategories() {
            return List.of(new GspmCategory(category, category));
        }

        @Override
        public Map<String, String> getAlertTags() {
            return Map.of();
        }

        @Override
        public boolean isEnabled() {
            return true;
        }

        @Override
        public void setEnabled(boolean enabled) {}

        @Override
        public AlertThreshold getAlertThreshold() {
            return AlertThreshold.MEDIUM;
        }

        @Override
        public void setAlertThreshold(AlertThreshold threshold) {}

        @Override
        public AttackStrength getAttackStrength() {
            return AttackStrength.MEDIUM;
        }

        @Override
        public void setAttackStrength(AttackStrength strength) {}
    }
}
