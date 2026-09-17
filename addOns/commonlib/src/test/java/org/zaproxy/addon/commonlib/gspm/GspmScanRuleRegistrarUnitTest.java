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
package org.zaproxy.addon.commonlib.gspm;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.zaproxy.addon.commonlib.gspm.GspmScanRuleRegistrar.RuleOwner;
import org.zaproxy.zap.control.AddOn;
import org.zaproxy.zap.extension.AddOnInstallationStatusListener.StatusUpdate;
import org.zaproxy.zap.extension.AddOnInstallationStatusListener.StatusUpdate.Status;

/**
 * Unit test for {@link GspmScanRuleRegistrar}, covering the add-on install/uninstall bookkeeping
 * shared by every scan-rule source (active scan, passive scan, ...), using simple fakes rather than
 * any tool-specific core API.
 */
class GspmScanRuleRegistrarUnitTest {

    private static final String TOOL = "tool";

    private GspmScanRuleRegistrar registrar;
    private GspmRegistry registry;
    private List<RuleOwner> allRules;
    private Map<AddOn, List<GspmRule>> installedRules;

    @BeforeEach
    void setUp() {
        registry = new GspmRegistry();
        allRules = new ArrayList<>();
        installedRules = new HashMap<>();
        registrar =
                new GspmScanRuleRegistrar(
                        TOOL,
                        () -> "Tool Display",
                        () -> new ArrayList<>(allRules),
                        addOn -> installedRules.getOrDefault(addOn, List.of()));
    }

    @Test
    void shouldRegisterToolAndAllRulesOnInitialRegistration() {
        // Given
        AddOn addOn = mock(AddOn.class);
        allRules.add(new RuleOwner(fakeRule(1), null));
        allRules.add(new RuleOwner(fakeRule(2), addOn));

        // When
        registrar.registerRulesWithGspm(registry);

        // Then
        assertThat(registry.getTool(TOOL).displayName(), is("Tool Display"));
        assertThat(registry.getRulesByTool(TOOL), hasSize(2));
        assertThat(registry.isRegistered(1), is(true));
        assertThat(registry.isRegistered(2), is(true));
    }

    @Test
    void shouldTrackAddOnOwnershipFromInitialRegistration() {
        // Given — rule 1 is tracked as owned by addOn from the initial bulk load, not an install
        // event.
        AddOn addOn = mock(AddOn.class);
        allRules.add(new RuleOwner(fakeRule(1), addOn));
        registrar.registerRulesWithGspm(registry);

        // When
        registrar.update(statusUpdate(Status.UNINSTALL, addOn));

        // Then
        assertThat(registry.isRegistered(1), is(false));
    }

    @Test
    void shouldRegisterRuleForInstalledAddOn() {
        // Given
        registrar.registerRulesWithGspm(registry);
        AddOn addOn = mock(AddOn.class);
        installedRules.put(addOn, List.of(fakeRule(10)));

        // When
        registrar.update(statusUpdate(Status.INSTALLED, addOn));

        // Then
        assertThat(registry.isRegistered(10), is(true));
    }

    @Test
    void shouldNotDoubleRegisterAlreadyRegisteredRuleOnInstall() {
        // Given
        registrar.registerRulesWithGspm(registry);
        AddOn addOn = mock(AddOn.class);
        installedRules.put(addOn, List.of(fakeRule(11)));
        registrar.update(statusUpdate(Status.INSTALLED, addOn));

        // When
        registrar.update(statusUpdate(Status.INSTALLED, addOn));

        // Then
        assertThat(registry.getRulesByTool(TOOL), hasSize(1));
    }

    @Test
    void shouldIgnoreOtherStatusUpdates() {
        // Given
        registrar.registerRulesWithGspm(registry);
        AddOn addOn = mock(AddOn.class);
        installedRules.put(addOn, List.of(fakeRule(12)));

        // When
        registrar.update(statusUpdate(Status.INSTALL, addOn));

        // Then
        assertThat(registry.getRulesByTool(TOOL), is(empty()));
    }

    @ParameterizedTest
    @EnumSource(
            value = Status.class,
            names = {"UNINSTALL", "SOFT_UNINSTALL"})
    void shouldUnregisterRulesOfUninstalledAddOnEvenIfSourceNoLongerReturnsThem(Status status) {
        // Given
        registrar.registerRulesWithGspm(registry);
        AddOn addOn = mock(AddOn.class);
        installedRules.put(addOn, List.of(fakeRule(13)));
        registrar.update(statusUpdate(Status.INSTALLED, addOn));
        assertThat(registry.isRegistered(13), is(true));
        // The rule source no longer has this add-on's rules by uninstall time.
        installedRules.remove(addOn);

        // When
        registrar.update(statusUpdate(status, addOn));

        // Then
        assertThat(registry.isRegistered(13), is(false));
    }

    @Test
    void shouldOnlyUnregisterRulesOfTheUninstalledAddOn() {
        // Given
        registrar.registerRulesWithGspm(registry);
        AddOn addOnA = mock(AddOn.class);
        AddOn addOnB = mock(AddOn.class);
        installedRules.put(addOnA, List.of(fakeRule(14)));
        installedRules.put(addOnB, List.of(fakeRule(15)));
        registrar.update(statusUpdate(Status.INSTALLED, addOnA));
        registrar.update(statusUpdate(Status.INSTALLED, addOnB));

        // When
        registrar.update(statusUpdate(Status.UNINSTALL, addOnA));

        // Then
        assertThat(registry.isRegistered(14), is(false));
        assertThat(registry.isRegistered(15), is(true));
    }

    @Test
    void shouldDoNothingWhenUninstallingAddOnWithNoRegisteredRules() {
        // Given
        registrar.registerRulesWithGspm(registry);
        AddOn addOn = mock(AddOn.class);

        // When / Then
        assertDoesNotThrow(() -> registrar.update(statusUpdate(Status.UNINSTALL, addOn)));
        assertThat(registry.getRulesByTool(TOOL), is(empty()));
    }

    @Test
    void shouldDoNothingWhenNotRegisteredWithGspm() {
        // Given — registerRulesWithGspm was never called.
        AddOn addOn = mock(AddOn.class);
        installedRules.put(addOn, List.of(fakeRule(16)));

        // When / Then
        assertDoesNotThrow(() -> registrar.update(statusUpdate(Status.INSTALLED, addOn)));
        assertDoesNotThrow(() -> registrar.update(statusUpdate(Status.UNINSTALL, addOn)));
    }

    @Test
    void shouldStopReactingToAddOnEventsAfterUnregisterRulesFromGspm() {
        // Given
        registrar.registerRulesWithGspm(registry);
        AddOn addOn = mock(AddOn.class);
        installedRules.put(addOn, List.of(fakeRule(17)));

        // When
        registrar.unregisterRulesFromGspm(registry);
        registrar.update(statusUpdate(Status.INSTALLED, addOn));

        // Then
        assertThat(registry.getAllRules(), is(empty()));
    }

    @Test
    void shouldRegisterRuleAddedDirectly() {
        // Given — e.g. a script-backed rule added at runtime, outside any add-on install.
        registrar.registerRulesWithGspm(registry);

        // When
        registrar.ruleAdded(fakeRule(20));

        // Then
        assertThat(registry.isRegistered(20), is(true));
    }

    @Test
    void shouldNotDoubleRegisterRuleAddedDirectlyTwice() {
        // Given
        registrar.registerRulesWithGspm(registry);
        registrar.ruleAdded(fakeRule(21));

        // When
        registrar.ruleAdded(fakeRule(21));

        // Then
        assertThat(registry.getRulesByTool(TOOL), hasSize(1));
    }

    @Test
    void shouldDoNothingWhenRuleAddedDirectlyWhileNotRegisteredWithGspm() {
        // Given — registerRulesWithGspm was never called.
        // When / Then
        assertDoesNotThrow(() -> registrar.ruleAdded(fakeRule(22)));
        assertThat(registry.getAllRules(), is(empty()));
    }

    @Test
    void shouldUnregisterRuleRemovedDirectly() {
        // Given — e.g. a script-backed rule removed at runtime, outside any add-on uninstall.
        registrar.registerRulesWithGspm(registry);
        registrar.ruleAdded(fakeRule(23));

        // When
        registrar.ruleRemoved(23);

        // Then
        assertThat(registry.isRegistered(23), is(false));
    }

    @Test
    void shouldDoNothingWhenRemovingRuleNotRegisteredDirectly() {
        // Given
        registrar.registerRulesWithGspm(registry);

        // When / Then
        assertDoesNotThrow(() -> registrar.ruleRemoved(99));
    }

    @Test
    void shouldDoNothingWhenRuleRemovedDirectlyWhileNotRegisteredWithGspm() {
        // Given — registerRulesWithGspm was never called.
        // When / Then
        assertDoesNotThrow(() -> registrar.ruleRemoved(24));
    }

    @Test
    void shouldNotReRegisterRuleRemovedDirectlyAfterUnregisterRulesFromGspm() {
        // Given
        registrar.registerRulesWithGspm(registry);
        registrar.ruleAdded(fakeRule(25));
        registrar.unregisterRulesFromGspm(registry);

        // When
        assertDoesNotThrow(() -> registrar.ruleRemoved(25));

        // Then
        assertThat(registry.getAllRules(), is(empty()));
    }

    private static GspmRule fakeRule(int id) {
        GspmRule rule = mock(GspmRule.class);
        lenient().when(rule.getId()).thenReturn(id);
        lenient().when(rule.getTool()).thenReturn(TOOL);
        return rule;
    }

    private static StatusUpdate statusUpdate(Status status, AddOn addOn) {
        return new StatusUpdate() {
            @Override
            public boolean isSuccessful() {
                return true;
            }

            @Override
            public Status getStatus() {
                return status;
            }

            @Override
            public AddOn getAddOn() {
                return addOn;
            }
        };
    }
}
