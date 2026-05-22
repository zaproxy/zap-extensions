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
package org.zaproxy.addon.client.ui;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.client.internal.ClientNode;

/** Unit test for {@link PopupMenuClientDelete}. */
class PopupMenuClientDeleteUnitTest {

    private ClientMapPanel clientMapPanel;
    private PopupMenuClientDelete menuItem;

    @BeforeEach
    void setUp() {
        clientMapPanel = mock(ClientMapPanel.class);
        menuItem = new PopupMenuClientDelete(clientMapPanel);
    }

    @Test
    void shouldDisableItemWhenOnlyRootSelected() {
        // Given
        ClientNode root = mock(ClientNode.class);
        given(root.isRoot()).willReturn(true);
        given(clientMapPanel.getSelectedNodes()).willReturn(List.of(root));

        // When
        boolean result = menuItem.isButtonEnabled();

        // Then
        assertThat(result, is(false));
    }

    @Test
    void shouldEnableItemWhenNonRootNodeSelected() {
        // Given
        ClientNode node = mock(ClientNode.class);
        given(node.isRoot()).willReturn(false);
        given(clientMapPanel.getSelectedNodes()).willReturn(List.of(node));

        // When
        boolean result = menuItem.isButtonEnabled();

        // Then
        assertThat(result, is(true));
    }

    @Test
    void shouldEnableItemWhenMultipleNodesSelected() {
        // Given
        ClientNode root = mock(ClientNode.class);
        given(root.isRoot()).willReturn(true);
        ClientNode node = mock(ClientNode.class);
        given(node.isRoot()).willReturn(false);
        given(clientMapPanel.getSelectedNodes()).willReturn(List.of(root, node));

        // When
        boolean result = menuItem.isButtonEnabled();

        // Then
        assertThat(result, is(true));
    }

    @Test
    void shouldEnableItemWhenNoNodesSelected() {
        // Given
        given(clientMapPanel.getSelectedNodes()).willReturn(List.of());

        // When
        boolean result = menuItem.isButtonEnabled();

        // Then
        assertThat(result, is(true));
    }
}
