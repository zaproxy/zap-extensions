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
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.zaproxy.addon.commonlib.ExtensionCommonlib;
import org.zaproxy.addon.commonlib.gspm.GspmCategory;
import org.zaproxy.addon.commonlib.gspm.GspmPhase;
import org.zaproxy.addon.commonlib.gspm.GspmRule;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link GspmCategoryTree}. */
class GspmCategoryTreeUnitTest extends TestUtils {

    private static final UnaryOperator<String> TOOL_NAMES = t -> "Tool " + t;

    private static final GspmCategory CB = new GspmCategory("browser", "Client Browser");
    private static final GspmCategory DAST = new GspmCategory("dast", "DAST");
    private static final GspmCategory IAST = new GspmCategory("iast", "IAST");
    private static final GspmCategory SAST = new GspmCategory("sast", "SAST");

    @BeforeAll
    static void setupMessages() {
        mockMessages(new ExtensionCommonlib());
    }

    @AfterAll
    static void cleanUpMessages() {
        Constant.messages = null;
    }

    @Test
    void shouldKeyNodesByPhaseThenCategoryIds() {
        // Given
        List<GspmRule> rules =
                List.of(
                        rule("ascan", 1, GspmPhase.ACTIVE, new GspmCategory("inject", "Inj")),
                        rule("pscan", 2, GspmPhase.PASSIVE, new GspmCategory("server-side", "SS")),
                        rule("wspscan", 3, GspmPhase.PASSIVE, new GspmCategory("websocket", "WS")));

        // When
        List<GspmCategoryTree.Node> nodes = GspmCategoryTree.build(rules, TOOL_NAMES);

        // Then
        assertThat(
                keys(nodes),
                contains(
                        "phase.active",
                        "phase.active.inject",
                        "phase.passive",
                        "phase.passive.server-side",
                        "phase.passive.websocket"));
        assertThat(nodes.get(0).path(), is(List.of()));
        assertThat(nodes.get(1).path(), contains("Active"));
        assertThat(nodes.get(1).label(), is("Active / Inj"));
    }

    @Test
    void shouldShareNodesBetweenToolsUsingTheSameCategoryIdsAndNestDeeperLevels() {
        // Given
        GspmRule ascan = rule("ascan", 10, GspmPhase.ACTIVE, CB);
        GspmRule dast = rule("ptk-dast", 200000, GspmPhase.ACTIVE, CB, DAST);
        GspmRule iast = rule("ptk-iast", 210000, GspmPhase.ACTIVE, CB, IAST);
        GspmRule dast2 = rule("ptk-dast", 200001, GspmPhase.ACTIVE, CB, DAST);
        GspmRule sast = rule("ptk-sast", 220000, GspmPhase.PASSIVE, CB, SAST);

        // When
        List<GspmCategoryTree.Node> nodes =
                GspmCategoryTree.build(List.of(ascan, dast, iast, dast2, sast), TOOL_NAMES);

        // Then
        assertThat(
                keys(nodes),
                contains(
                        "phase.active",
                        "phase.active.browser",
                        "phase.active.browser.dast",
                        "phase.active.browser.iast",
                        "phase.passive",
                        "phase.passive.browser",
                        "phase.passive.browser.sast"));
        assertThat(nodes.get(1).displayName(), is("Client Browser"));
        assertThat(nodes.get(2).path(), contains("Active", "Client Browser"));
        assertThat(nodes.get(2).label(), is("Active / Client Browser / DAST"));
        assertThat(nodes.get(6).label(), is("Passive / Client Browser / SAST"));
        assertThat(GspmCategoryTree.belongsTo(ascan, "phase.active.browser"), is(true));
        assertThat(GspmCategoryTree.belongsTo(dast, "phase.active.browser"), is(true));
    }

    @Test
    void shouldDisambiguateSiblingsWithTheSameDisplayName() {
        // Given
        GspmCategory misc = new GspmCategory("misc", "Misc");
        GspmCategory otherMisc = new GspmCategory("other", "misc");
        List<GspmRule> rules =
                List.of(
                        rule("a", 1, GspmPhase.ACTIVE, CB, misc),
                        rule("b", 2, GspmPhase.ACTIVE, CB, otherMisc));

        // When
        List<GspmCategoryTree.Node> nodes = GspmCategoryTree.build(rules, TOOL_NAMES);

        // Then
        assertThat(nodes.get(2).displayName(), is("Misc"));
        assertThat(nodes.get(3).displayName(), is("misc (Tool b)"));
    }

    @Test
    void shouldReportWhichRulesBelongToEachNode() {
        // Given
        GspmRule dast = rule("ptk-dast", 200000, GspmPhase.ACTIVE, CB, DAST);
        GspmRule iast = rule("ptk-iast", 210000, GspmPhase.ACTIVE, CB, IAST);
        GspmRule sast = rule("ptk-sast", 220000, GspmPhase.PASSIVE, CB, SAST);

        // When / Then
        assertThat(GspmCategoryTree.belongsTo(dast, "all"), is(true));
        assertThat(GspmCategoryTree.belongsTo(dast, "phase.active"), is(true));
        assertThat(GspmCategoryTree.belongsTo(iast, "phase.active.browser"), is(true));
        assertThat(GspmCategoryTree.belongsTo(sast, "phase.active.browser"), is(false));
        assertThat(GspmCategoryTree.belongsTo(dast, "phase.active.browser.dast"), is(true));
        assertThat(GspmCategoryTree.belongsTo(iast, "phase.active.browser.dast"), is(false));
    }

    @Test
    void shouldResolveKeysViaTheirAncestorsThenAll() {
        assertThat(
                parentKeys("phase.active.browser.dast"),
                contains("phase.active.browser", "phase.active", "all"));
        assertThat(parentKeys("phase.passive"), contains("all"));
        assertThat(parentKeys("all"), is(List.of()));
        assertThat(GspmCategoryTree.parentKey(null), is(nullValue()));
    }

    @Test
    void shouldResolveUnrecognisedKeysToAll() {
        assertThat(parentKeys("unknown"), contains("all"));
    }

    private static List<String> parentKeys(String key) {
        List<String> chain = new ArrayList<>();
        for (String k = GspmCategoryTree.parentKey(key);
                k != null;
                k = GspmCategoryTree.parentKey(k)) {
            chain.add(k);
        }
        return chain;
    }

    private static List<String> keys(List<GspmCategoryTree.Node> nodes) {
        return nodes.stream().map(GspmCategoryTree.Node::key).toList();
    }

    private static GspmRule rule(String tool, int id, GspmPhase phase, GspmCategory... cats) {
        List<GspmCategory> categories = List.of(cats);
        return new GspmRule() {
            @Override
            public int getId() {
                return id;
            }

            @Override
            public String getName() {
                return tool + "-" + id;
            }

            @Override
            public String getTool() {
                return tool;
            }

            @Override
            public GspmPhase getPhase() {
                return phase;
            }

            @Override
            public List<GspmCategory> getCategories() {
                return categories;
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
                return null;
            }

            @Override
            public void setAttackStrength(AttackStrength strength) {}
        };
    }
}
