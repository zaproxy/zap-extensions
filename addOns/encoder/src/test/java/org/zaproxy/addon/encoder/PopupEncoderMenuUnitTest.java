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
package org.zaproxy.addon.encoder;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import javax.swing.JButton;
import javax.swing.JPopupMenu;
import javax.swing.text.JTextComponent;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit tests for {@link PopupEncoderMenu}. */
class PopupEncoderMenuUnitTest extends TestUtils {

    @BeforeAll
    static void initMessages() {
        mockMessages(new ExtensionEncoder());
        Constant.getInstance();
        Model model = new Model();
        Model.setSingletonForTesting(model);
        Control.initSingletonForTesting(model);
    }

    @Test
    void shouldNotBeEnabledForNonTextComponent() {
        // Given
        PopupEncoderMenu menu = createMenu();
        JButton button = mock(JButton.class);

        // When
        boolean result = menu.isEnableForComponent(button);

        // Then
        assertThat(result, is(false));
    }

    @Test
    void shouldBeEnabledForTextComponentWithSelection() {
        // Given
        PopupEncoderMenu menu = createMenu();
        JTextComponent textComponent = mock(JTextComponent.class);
        given(textComponent.getSelectedText()).willReturn("selected");

        // When
        boolean result = menu.isEnableForComponent(textComponent);

        // Then
        assertThat(result, is(true));
        assertThat(menu.isEnabled(), is(true));
    }

    @Test
    void shouldBeEnabledButDisabledForTextComponentWithNoSelection() {
        // Given
        PopupEncoderMenu menu = createMenu();
        JTextComponent textComponent = mock(JTextComponent.class);
        given(textComponent.getSelectedText()).willReturn(null);

        // When
        boolean result = menu.isEnableForComponent(textComponent);

        // Then
        assertThat(result, is(true));
        assertThat(menu.isEnabled(), is(false));
    }

    @Test
    void shouldNotBeEnabledForEncodeDecodeInputField() {
        // Given
        PopupEncoderMenu menu = createMenu();
        JTextComponent textComponent = mock(JTextComponent.class);
        given(textComponent.getName()).willReturn(EncodeDecodeDialog.ENCODE_DECODE_FIELD);

        // When
        boolean result = menu.isEnableForComponent(textComponent);

        // Then
        assertThat(result, is(false));
    }

    @Test
    void shouldNotBeEnabledForEncodeDecodeResultField() {
        // Given
        PopupEncoderMenu menu = createMenu();
        JTextComponent textComponent = mock(JTextComponent.class);
        given(textComponent.getName()).willReturn(EncodeDecodeDialog.ENCODE_DECODE_RESULTFIELD);

        // When
        boolean result = menu.isEnableForComponent(textComponent);

        // Then
        assertThat(result, is(false));
    }

    @Test
    void shouldBuildSubmenusForAllCategories() {
        // Given / When
        PopupEncoderMenu menu = createMenu();

        // Then - should have category submenus (plus the dialog item in the popup)
        JPopupMenu popupMenu = menu.getPopupMenu();
        assertThat(popupMenu.getComponentCount(), is(greaterThan(0)));
    }

    private static PopupEncoderMenu createMenu() {
        return new PopupEncoderMenu(() -> {});
    }
}
