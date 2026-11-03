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
import static org.hamcrest.Matchers.empty;

import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.commonlib.ExtensionCommonlib;
import org.zaproxy.zap.testutils.TestUtils;

class GspmTagChooserPanelUnitTest extends TestUtils {

    @BeforeAll
    static void setupMessages() {
        mockMessages(new ExtensionCommonlib());
    }

    @AfterAll
    static void cleanUpMessages() {
        Constant.messages = null;
    }

    @Test
    void shouldKeepInitiallySelectedTagsThatAreNotAvailable() {
        // Given
        GspmTagChooserPanel panel =
                new GspmTagChooserPanel(List.of("A", "B"), List.of("B", "REMOVED_ADDON_TAG"));

        // When
        List<String> selected = panel.getSelectedTags();

        // Then
        assertThat(selected, contains("B", "REMOVED_ADDON_TAG"));
    }

    @Test
    void shouldKeepSelectionsWhenFilterIsNarrowedAndCleared() {
        // Given
        GspmTagChooserPanel panel =
                new GspmTagChooserPanel(List.of("A", "B", "C"), List.of("A", "B"));

        // When
        panel.setFilter("A");
        panel.setFilter("");

        // Then
        assertThat(panel.getSelectedTags(), contains("A", "B"));
    }

    @Test
    void shouldKeepSelectionsHiddenByFilter() {
        // Given
        GspmTagChooserPanel panel = new GspmTagChooserPanel(List.of("A", "B"), List.of("B"));

        // When
        panel.setFilter("A");

        // Then
        assertThat(panel.getSelectedTags(), contains("B"));
    }

    @Test
    void shouldHaveNoSelectionWhenNothingInitiallySelected() {
        // Given / When
        GspmTagChooserPanel panel = new GspmTagChooserPanel(List.of("A"), List.of());

        // Then
        assertThat(panel.getSelectedTags(), empty());
    }
}
