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
package org.zaproxy.addon.commonlib.ui;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.swing.tree.TreeNode;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.SiteNode;
import org.zaproxy.addon.commonlib.ExtensionCommonlib;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.view.HrefTypeInfo;

/** Unit test for {@link SitesTreeInfoMenu}. */
class SitesTreeInfoMenuUnitTest extends TestUtils {

    private static final int TYPE_A = -5;
    private static final int TYPE_AA = -6;
    private static final int TYPE_B = -7;
    private static final int TYPE_X = -8;

    private static List<HrefTypeInfo> customTypes;

    @BeforeAll
    static void beforeAll() {
        mockMessages(new ExtensionCommonlib());

        customTypes =
                List.of(
                        new HrefTypeInfo(TYPE_A, "A"),
                        new HrefTypeInfo(TYPE_AA, "Aa"),
                        new HrefTypeInfo(TYPE_B, "B"),
                        new HrefTypeInfo(TYPE_X, "X"));

        customTypes.forEach(HrefTypeInfo::addType);
    }

    @AfterAll
    static void afterAll() {
        customTypes.forEach(HrefTypeInfo::removeType);
    }

    @Test
    void shouldIncludeUnknownLastAddedWhenSubtreeHasNoHistory() {
        // Given
        SiteNode root = mockNodeWithChildren(List.of());

        // When
        String result = SitesTreeInfoMenu.createSummary(root);

        // Then
        assertThat(result, containsString("Last added: (no history)"));
    }

    @Test
    void shouldIncludeNoSourceDataWhenSubtreeHasNoHistory() {
        // Given
        SiteNode root = mockNodeWithChildren(List.of());

        // When
        String result = SitesTreeInfoMenu.createSummary(root);

        // Then
        assertThat(
                result,
                containsString(
                        """
                        Sources:
                        (no source data available)"""));
    }

    @Test
    void shouldReturnFullSummaryForSubtree() {
        // Given
        long timestamp = 1000L;
        SiteNode root = mockNodeWithChildren(List.of(mockLeafNode(TYPE_AA, timestamp)));

        // When
        String result = SitesTreeInfoMenu.createSummary(root);

        // Then
        assertThat(
                result,
                is(
                        equalTo(
                                """
                                Nodes in subtree: 2
                                Last added: %s

                                Sources:
                                  Aa: 1"""
                                        .formatted(
                                                SitesTreeInfoMenu.LAST_ADDED_FORMAT.format(
                                                        Instant.ofEpochMilli(timestamp))))));
    }

    @Test
    void shouldSortSourcesByCountDescThenLabelAsc() {
        // Given
        List<TreeNode> children = new ArrayList<>();
        addLeafNodes(children, TYPE_A, 1);
        addLeafNodes(children, TYPE_AA, 5);
        addLeafNodes(children, TYPE_B, 5);
        addLeafNodes(children, TYPE_X, 3);
        SiteNode root = mockNodeWithChildren(children);

        // When
        String result = SitesTreeInfoMenu.createSummary(root);

        // Then
        assertThat(
                result,
                containsString(
                        """
                        Sources:
                          Aa: 5
                          B: 5
                          X: 3
                          A: 1"""));
    }

    private void addLeafNodes(List<TreeNode> children, int historyType, int count) {
        for (int i = 0; i < count; i++) {
            children.add(mockLeafNode(historyType));
        }
    }

    private static SiteNode mockLeafNode(int historyType) {
        return mockLeafNode(historyType, 1L);
    }

    private static SiteNode mockLeafNode(int historyType, long timestamp) {
        SiteNode node = mock(withSettings().strictness(Strictness.LENIENT));
        HistoryReference href = mock(withSettings().strictness(Strictness.LENIENT));
        given(href.getHistoryType()).willReturn(historyType);
        given(href.getTimeSentMillis()).willReturn(timestamp);
        given(node.getHistoryReference()).willReturn(href);
        given(node.children()).willReturn(Collections.emptyEnumeration());
        return node;
    }

    private static SiteNode mockNodeWithChildren(List<TreeNode> children) {
        SiteNode node = mock(withSettings().strictness(Strictness.LENIENT));
        given(node.children()).willReturn(Collections.enumeration(children));
        return node;
    }
}
