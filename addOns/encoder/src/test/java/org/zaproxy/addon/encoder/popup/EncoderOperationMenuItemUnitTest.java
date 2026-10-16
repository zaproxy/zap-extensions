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
package org.zaproxy.addon.encoder.popup;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import javax.swing.JPanel;
import javax.swing.text.JTextComponent;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.zaproxy.addon.encoder.EncodeDecodeDialog;
import org.zaproxy.addon.encoder.ExtensionEncoder;
import org.zaproxy.addon.encoder.processors.EncodeDecodeProcessor;
import org.zaproxy.addon.encoder.processors.EncodeDecodeResult;
import org.zaproxy.zap.extension.httppanel.HttpPanelResponse;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit tests for {@link EncoderOperationMenuItem}. */
class EncoderOperationMenuItemUnitTest extends TestUtils {

    @BeforeAll
    static void initMessages() {
        mockMessages(new ExtensionEncoder());
    }

    @AfterEach
    void clearInvoker() {
        EncoderOperationMenuItem.setCurrentInvoker(null);
    }

    @Test
    void shouldNotBeEnabledForNonEditableTextComponent() {
        EncoderOperationMenuItem menuItem = createMenuItem();
        JTextComponent textComponent =
                mock(JTextComponent.class, withSettings().strictness(Strictness.LENIENT));
        given(textComponent.isEditable()).willReturn(false);
        given(textComponent.getSelectedText()).willReturn("selected");

        assertThat(menuItem.isEnableForComponent(textComponent), is(false));
    }

    @Test
    void shouldNotBeEnabledForEncodeDecodeInputField() {
        EncoderOperationMenuItem menuItem = createMenuItem();
        JTextComponent textComponent =
                mock(JTextComponent.class, withSettings().strictness(Strictness.LENIENT));
        given(textComponent.getName()).willReturn(EncodeDecodeDialog.ENCODE_DECODE_FIELD);

        assertThat(menuItem.isEnableForComponent(textComponent), is(false));
    }

    @Test
    void shouldNotBeEnabledForEncodeDecodeResultField() {
        EncoderOperationMenuItem menuItem = createMenuItem();
        JTextComponent textComponent =
                mock(JTextComponent.class, withSettings().strictness(Strictness.LENIENT));
        given(textComponent.getName()).willReturn(EncodeDecodeDialog.ENCODE_DECODE_RESULTFIELD);

        assertThat(menuItem.isEnableForComponent(textComponent), is(false));
    }

    @Test
    void shouldNotBeEnabledWhenParentIsResponseView() {
        EncoderOperationMenuItem menuItem = createMenuItem();
        JTextComponent textComponent =
                mock(JTextComponent.class, withSettings().strictness(Strictness.LENIENT));
        HttpPanelResponse responsePanel = mock(HttpPanelResponse.class);
        JPanel parent = mock(JPanel.class);
        given(textComponent.getParent()).willReturn(parent);
        given(parent.getParent()).willReturn(responsePanel);

        assertThat(menuItem.isEnableForComponent(textComponent), is(false));
    }

    @Test
    void shouldBeEnabledForEditableTextComponentWithSelection() {
        EncoderOperationMenuItem menuItem = createMenuItem();
        JTextComponent textComponent =
                mock(JTextComponent.class, withSettings().strictness(Strictness.LENIENT));
        given(textComponent.isEditable()).willReturn(true);
        given(textComponent.getSelectedText()).willReturn("selected");

        assertThat(menuItem.isEnableForComponent(textComponent), is(true));
        assertThat(menuItem.isEnabled(), is(true));
    }

    @Test
    void shouldBeEnabledButDisabledForTextComponentWithNoSelection() {
        EncoderOperationMenuItem menuItem = createMenuItem();
        JTextComponent textComponent =
                mock(JTextComponent.class, withSettings().strictness(Strictness.LENIENT));
        given(textComponent.isEditable()).willReturn(true);
        given(textComponent.getSelectedText()).willReturn(null);

        assertThat(menuItem.isEnableForComponent(textComponent), is(true));
        assertThat(menuItem.isEnabled(), is(false));
    }

    @Test
    void shouldProcessTextViaCurrentInvoker() throws Exception {
        // Given
        EncodeDecodeProcessor processor = value -> new EncodeDecodeResult("processed-" + value);
        EncoderOperationMenuItem menuItem = createMenuItem(processor);

        JTextComponent textComponent =
                mock(JTextComponent.class, withSettings().strictness(Strictness.LENIENT));
        given(textComponent.getSelectedText()).willReturn("hello");
        given(textComponent.getSelectionStart()).willReturn(0);
        given(textComponent.getSelectionEnd()).willReturn(5);

        EncoderOperationMenuItem.setCurrentInvoker(textComponent);

        // When
        menuItem.performAction();

        // Then
        Thread.sleep(1000);
        verify(textComponent).replaceSelection("processed-hello");
    }

    @Test
    void shouldNotThrowWhenNoInvoker() {
        EncoderOperationMenuItem menuItem = createMenuItem();
        EncoderOperationMenuItem.setCurrentInvoker(null);
        menuItem.performAction();
    }

    private static EncoderOperationMenuItem createMenuItem() {
        return createMenuItem(value -> new EncodeDecodeResult("encoded-" + value));
    }

    private static EncoderOperationMenuItem createMenuItem(EncodeDecodeProcessor processor) {
        return new EncoderOperationMenuItem("Test", processor);
    }
}
