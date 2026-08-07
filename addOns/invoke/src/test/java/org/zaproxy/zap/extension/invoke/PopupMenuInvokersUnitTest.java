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
package org.zaproxy.zap.extension.invoke;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import java.util.List;
import javax.swing.JMenuItem;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.testutils.TestUtils;

class PopupMenuInvokersUnitTest extends TestUtils {

    private PopupMenuInvokers popupMenu;

    @BeforeEach
    void setUp() {
        mockMessages(new ExtensionInvoke());
        popupMenu = new PopupMenuInvokers();
    }

    @Test
    void shouldUseTitleCapitalizationForMenuLabel() {
        assertThat(popupMenu.getText(), is("Run Application"));
    }

    @Test
    void shouldPreserveConfiguredApplicationNameCapitalization() {
        // Given
        InvokableApp app = new InvokableApp();
        app.setDisplayName("my custom application");

        // When
        popupMenu.setApps(List.of(app));

        // Then
        JMenuItem applicationMenuItem = (JMenuItem) popupMenu.getMenuComponent(0);
        assertThat(applicationMenuItem.getText(), is("my custom application"));
    }
}
