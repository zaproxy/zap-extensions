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
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.zaproxy.addon.commonlib.ExtensionCommonlib;
import org.zaproxy.addon.commonlib.gspm.GspmRuleSet;
import org.zaproxy.zap.testutils.TestUtils;

class GspmRuleSetTableModelUnitTest extends TestUtils {

    @BeforeAll
    static void setupMessages() {
        mockMessages(new ExtensionCommonlib());
    }

    @AfterAll
    static void cleanUpMessages() {
        Constant.messages = null;
    }

    private static GspmRuleSetTableModel modelFor(GspmRuleSet rs) {
        GspmRuleSetTableModel model = new GspmRuleSetTableModel();
        model.setRuleSets(List.of(rs));
        return model;
    }

    @Test
    void shouldShowNoOverrideForUnsetThresholdAndStrength() {
        // Given
        GspmRuleSetTableModel model = modelFor(new GspmRuleSet());

        // When / Then
        String none = GspmRuleSetTableModel.noOverrideLabel();
        assertThat(model.getValueAt(0, GspmRuleSetTableModel.COL_THRESHOLD), is(none));
        assertThat(model.getValueAt(0, GspmRuleSetTableModel.COL_STRENGTH), is(none));
    }

    @Test
    void shouldShowLevelForSetThresholdAndStrength() {
        // Given
        GspmRuleSet rs = new GspmRuleSet();
        rs.setThresholdEnum(AlertThreshold.HIGH);
        rs.setStrengthEnum(AttackStrength.LOW);
        GspmRuleSetTableModel model = modelFor(rs);

        // When / Then
        assertThat(
                model.getValueAt(0, GspmRuleSetTableModel.COL_THRESHOLD),
                is(model.thresholdToI18n(AlertThreshold.HIGH)));
        assertThat(
                model.getValueAt(0, GspmRuleSetTableModel.COL_STRENGTH),
                is(model.strengthToI18n(AttackStrength.LOW)));
    }

    @Test
    void shouldClearThresholdWithoutAffectingStrengthWhenNoOverrideSet() {
        // Given
        GspmRuleSet rs = new GspmRuleSet();
        rs.setThresholdEnum(AlertThreshold.HIGH);
        rs.setStrengthEnum(AttackStrength.LOW);
        GspmRuleSetTableModel model = modelFor(rs);

        // When
        model.setValueAt(
                GspmRuleSetTableModel.noOverrideLabel(), 0, GspmRuleSetTableModel.COL_THRESHOLD);

        // Then
        assertThat(rs.getThreshold(), is(nullValue()));
        assertThat(rs.getStrength(), is(AttackStrength.LOW.name()));
    }

    @Test
    void shouldClearStrengthWithoutAffectingThresholdWhenNoOverrideSet() {
        // Given
        GspmRuleSet rs = new GspmRuleSet();
        rs.setThresholdEnum(AlertThreshold.HIGH);
        rs.setStrengthEnum(AttackStrength.LOW);
        GspmRuleSetTableModel model = modelFor(rs);

        // When
        model.setValueAt(
                GspmRuleSetTableModel.noOverrideLabel(), 0, GspmRuleSetTableModel.COL_STRENGTH);

        // Then
        assertThat(rs.getStrength(), is(nullValue()));
        assertThat(rs.getThreshold(), is(AlertThreshold.HIGH.name()));
    }
}
