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

import java.awt.event.ActionEvent;
import javax.swing.JButton;
import javax.swing.JTree;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Unit test for {@link PopupMenuItemClient}. */
class PopupMenuItemClientUnitTest {

    private ClientMapPanel clientMapPanel;

    @BeforeEach
    void setup() {
        clientMapPanel = mock(ClientMapPanel.class);
    }

    @Test
    void shouldReturnTrueForIsButtonEnabledByDefault() {
        // Given / When
        PopupMenuItemClient menuItem =
                new PopupMenuItemClient("Name", clientMapPanel) {
                    @Override
                    void performAction(ActionEvent e) {
                        // Nothing to do.
                    }
                };

        // Then
        assertThat(menuItem.isButtonEnabled(), is(true));
    }

    @Test
    void shouldNotBeEnabledForNonTreeComponent() {
        // Given
        PopupMenuItemClient menuItem = new TestPopupMenuItemClient(clientMapPanel);
        JButton nonTree = mock(JButton.class);

        // When
        boolean result = menuItem.isEnableForComponent(nonTree);

        // Then
        assertThat(result, is(false));
    }

    @Test
    void shouldNotBeEnabledForTreeWithWrongName() {
        // Given
        PopupMenuItemClient menuItem = new TestPopupMenuItemClient(clientMapPanel);
        JTree tree = createTree("otherTree");

        // When
        boolean result = menuItem.isEnableForComponent(tree);

        // Then
        assertThat(result, is(false));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldReflectButtonEnabledStateForClientTree(boolean state) {
        // Given
        PopupMenuItemClient menuItem = new TestPopupMenuItemClient(clientMapPanel, state);
        JTree tree = createClientTree();

        // When
        boolean result = menuItem.isEnableForComponent(tree);

        // Then
        assertThat(result, is(true));
        assertThat(menuItem.isEnabled(), is(state));
    }

    private static JTree createClientTree() {
        return createTree(ClientMapPanel.CLIENT_TREE_NAME);
    }

    private static JTree createTree(String name) {
        JTree tree = mock(JTree.class);
        given(tree.getName()).willReturn(name);
        return tree;
    }

    private static class TestPopupMenuItemClient extends PopupMenuItemClient {

        private static final long serialVersionUID = 1L;

        private final boolean buttonEnabled;

        TestPopupMenuItemClient(ClientMapPanel clientMapPanel) {
            this(clientMapPanel, false);
        }

        TestPopupMenuItemClient(ClientMapPanel clientMapPanel, boolean buttonEnabled) {
            super("Test", clientMapPanel);

            this.buttonEnabled = buttonEnabled;
        }

        @Override
        protected boolean isButtonEnabled() {
            return buttonEnabled;
        }

        @Override
        void performAction(ActionEvent e) {
            // Nothing to do.
        }
    }
}
