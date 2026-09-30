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
package org.zaproxy.zap.extension.websocket.pscan;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.anEmptyMap;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.commonlib.gspm.GspmRegistry;
import org.zaproxy.addon.commonlib.gspm.GspmRule;
import org.zaproxy.addon.commonlib.gspm.GspmScanRuleRegistrar;
import org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata;
import org.zaproxy.zap.control.AddOn;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.websocket.pscan.scripts.WebSocketPassiveScriptScanRule;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.I18N;

class GspmWebSocketPassiveScanRegistrarUnitTest extends TestUtils {

    private GspmWebSocketPassiveScanRegistrar registrar;
    private GspmScanRuleRegistrar scanRuleRegistrar;
    private GspmRegistry registry;
    private WebSocketPassiveScannerManager scannersManager;
    private List<WebSocketPassiveScanner> scanners;

    @BeforeEach
    void setUp() throws Exception {
        I18N i18n = mock(I18N.class, withSettings().strictness(Strictness.LENIENT));
        given(i18n.getString(anyString())).willReturn("");
        given(i18n.getString(anyString(), any())).willReturn("");
        Constant.messages = i18n;

        scannersManager = mock(WebSocketPassiveScannerManager.class);
        scanners = new ArrayList<>();
        lenient().when(scannersManager.getScanners()).thenAnswer(inv -> new ArrayList<>(scanners));

        registrar = new GspmWebSocketPassiveScanRegistrar(scannersManager);
        registry = new GspmRegistry();

        scanRuleRegistrar = (GspmScanRuleRegistrar) getField(registrar, "scanRuleRegistrar");
        // Registers the tool and sets scanRuleRegistrar's registry; scanners is empty at this
        // point, so this registers zero rules.
        scanRuleRegistrar.registerRulesWithGspm(registry);
    }

    @AfterAll
    static void cleanUp() {
        Constant.messages = null;
    }

    @Test
    void shouldRegisterAllScannersOnInitialRegistration() {
        // Given
        scanners.add(scannerWithId(200, "Rule A"));
        scanners.add(scannerWithId(201, "Rule B"));

        // When
        scanRuleRegistrar.registerRulesWithGspm(registry);

        // Then
        List<GspmRule> rules = registry.getRulesByTool(GspmWebSocketPassiveScanRegistrar.TOOL);
        assertThat(rules, hasSize(2));
        assertThat(rules.stream().map(GspmRule::getId).toList(), containsInAnyOrder(200, 201));
    }

    @Test
    void shouldRegisterRuleAddedDirectly() {
        // Given — e.g. a script-backed rule, added at runtime via
        // WebSocketPassiveScannerManager.add().
        WebSocketPassiveScanner scanner = scannerWithId(101, "Extra Rule");

        // When
        registrar.ruleAdded(scanner);

        // Then
        assertThat(registry.isRegistered(101), is(true));
        List<GspmRule> rules = registry.getRulesByTool(GspmWebSocketPassiveScanRegistrar.TOOL);
        assertThat(rules, hasSize(1));
        assertThat(rules.get(0).getId(), is(101));
        assertThat(rules.get(0).getAddOnName(), is(nullValue()));
    }

    @Test
    void shouldUnregisterRuleRemovedDirectly() {
        // Given
        registrar.ruleAdded(scannerWithId(106, "Rule"));
        assertThat(registry.isRegistered(106), is(true));

        // When
        registrar.ruleRemoved(106);

        // Then
        assertThat(registry.isRegistered(106), is(false));
    }

    @Test
    void shouldDelegateEnabledStateToManager() {
        // Given
        WebSocketPassiveScanner scanner = scannerWithId(300, "Rule");
        lenient().when(scannersManager.isEnabled(scanner)).thenReturn(true);
        registrar.ruleAdded(scanner);

        // When
        GspmRule rule = registry.getRulesByTool(GspmWebSocketPassiveScanRegistrar.TOOL).get(0);

        // Then
        assertThat(rule.isEnabled(), is(true));
        rule.setEnabled(false);
        // The setter must delegate to the manager, not track state locally.
        verify(scannersManager).setEnable(scanner, false);
    }

    @Test
    void shouldReturnStatusAndAlertTagsFromScriptScanRule() throws Exception {
        // Given
        var metadata = new ScanRuleMetadata(400, "Script Rule");
        metadata.setStatus(AddOn.Status.beta);
        var script = mock(ScriptWrapper.class);
        WebSocketPassiveScriptScanRule scanRule =
                new WebSocketPassiveScriptScanRule(script, metadata);

        // When
        registrar.ruleAdded(scanRule);

        // Then
        GspmRule rule = registry.getRulesByTool(GspmWebSocketPassiveScanRegistrar.TOOL).get(0);
        assertThat(rule.getStatus(), is(AddOn.Status.beta));
    }

    @Test
    void shouldReturnUnknownStatusForNonScriptScanner() {
        // Given
        WebSocketPassiveScanner scanner = scannerWithId(401, "Compiled Rule");

        // When
        registrar.ruleAdded(scanner);

        // Then
        GspmRule rule = registry.getRulesByTool(GspmWebSocketPassiveScanRegistrar.TOOL).get(0);
        assertThat(rule.getStatus(), is(AddOn.Status.unknown));
        assertThat(rule.getAlertTags(), is(anEmptyMap()));
    }

    @Test
    void shouldHaveNoAddOnRulesFromAddOnInstallDrivenPath() throws Exception {
        // Given — websocket passive rules have no add-on attribution mechanism yet (see class
        // javadoc), so the add-on-install-driven supplier GspmScanRuleRegistrar also supports
        // must contribute nothing.
        @SuppressWarnings("unchecked")
        Function<AddOn, List<GspmRule>> rulesForAddOn =
                (Function<AddOn, List<GspmRule>>) getField(scanRuleRegistrar, "rulesForAddOn");

        // When
        List<GspmRule> rules = rulesForAddOn.apply(mock(AddOn.class));

        // Then
        assertThat(rules, is(empty()));
    }

    private static Object getField(Object target, String name) throws Exception {
        Field field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        return field.get(target);
    }

    private static WebSocketPassiveScanner scannerWithId(int id, String name) {
        WebSocketPassiveScanner scanner = mock(WebSocketPassiveScanner.class);
        lenient().when(scanner.getId()).thenReturn(id);
        lenient().when(scanner.getName()).thenReturn(name);
        return scanner;
    }
}
