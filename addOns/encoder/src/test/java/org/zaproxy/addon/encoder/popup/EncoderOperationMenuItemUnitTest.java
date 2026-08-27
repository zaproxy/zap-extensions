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
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import javax.swing.JPanel;
import javax.swing.text.JTextComponent;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.Model;
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
        Constant.getInstance();
        Model model = new Model();
        Model.setSingletonForTesting(model);
        Control.initSingletonForTesting(model);
    }

    @Test
    void shouldNotBeEnabledForNonEditableTextComponent() {
        // Given
        EncoderOperationMenuItem menuItem = createMenuItem();
        JTextComponent textComponent =
                mock(JTextComponent.class, withSettings().strictness(Strictness.LENIENT));
        given(textComponent.isEditable()).willReturn(false);
        given(textComponent.getSelectedText()).willReturn("selected");

        // When
        boolean result = menuItem.isEnableForComponent(textComponent);

        // Then
        assertThat(result, is(false));
    }

    @Test
    void shouldNotBeEnabledForEncodeDecodeInputField() {
        // Given
        EncoderOperationMenuItem menuItem = createMenuItem();
        JTextComponent textComponent =
                mock(JTextComponent.class, withSettings().strictness(Strictness.LENIENT));
        given(textComponent.getName()).willReturn(EncodeDecodeDialog.ENCODE_DECODE_FIELD);

        // When
        boolean result = menuItem.isEnableForComponent(textComponent);

        // Then
        assertThat(result, is(false));
    }

    @Test
    void shouldNotBeEnabledForEncodeDecodeResultField() {
        // Given
        EncoderOperationMenuItem menuItem = createMenuItem();
        JTextComponent textComponent =
                mock(JTextComponent.class, withSettings().strictness(Strictness.LENIENT));
        given(textComponent.getName()).willReturn(EncodeDecodeDialog.ENCODE_DECODE_RESULTFIELD);

        // When
        boolean result = menuItem.isEnableForComponent(textComponent);

        // Then
        assertThat(result, is(false));
    }

    @Test
    void shouldNotBeEnabledWhenParentIsResponseView() {
        // Given
        EncoderOperationMenuItem menuItem = createMenuItem();
        JTextComponent textComponent =
                mock(JTextComponent.class, withSettings().strictness(Strictness.LENIENT));
        HttpPanelResponse responsePanel = mock(HttpPanelResponse.class);
        JPanel parent = mock(JPanel.class);
        given(textComponent.getParent()).willReturn(parent);
        given(parent.getParent()).willReturn(responsePanel);

        // When
        boolean result = menuItem.isEnableForComponent(textComponent);

        // Then
        assertThat(result, is(false));
    }

    @Test
    void shouldNotApplyResultWhenSelectionChangedDuringProcessing() throws Exception {
        // Given
        java.util.concurrent.CountDownLatch processingStarted =
                new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch continueProcessing =
                new java.util.concurrent.CountDownLatch(1);
        EncodeDecodeProcessor processor =
                value -> {
                    processingStarted.countDown();
                    try {
                        continueProcessing.await();
                    } catch (InterruptedException ignored) {
                        Thread.currentThread().interrupt();
                    }
                    return new EncodeDecodeResult("processed-" + value);
                };
        EncoderOperationMenuItem menuItem = createMenuItem(processor);

        JTextComponent textComponent =
                mock(JTextComponent.class, withSettings().strictness(Strictness.LENIENT));
        given(textComponent.isEditable()).willReturn(true);
        given(textComponent.getSelectedText()).willReturn("hello");
        given(textComponent.getSelectionStart()).willReturn(0);
        given(textComponent.getSelectionEnd()).willReturn(5);
        menuItem.isEnableForComponent(textComponent);

        // When - trigger the action, then change selection before processing completes
        new Thread(() -> menuItem.performAction()).start();
        processingStarted.await();

        // Simulate: user changes selection before processing completes
        given(textComponent.getSelectionStart()).willReturn(10);
        given(textComponent.getSelectionEnd()).willReturn(20);
        given(textComponent.getSelectedText()).willReturn("different");

        // Let processing complete
        continueProcessing.countDown();

        // Then - replaceSelection should not have been called
        verify(textComponent, timeout(1000).times(0))
                .replaceSelection(org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void shouldApplyResultWhenSelectionUnchanged() throws Exception {
        // Given
        EncodeDecodeProcessor processor = value -> new EncodeDecodeResult("processed-" + value);
        EncoderOperationMenuItem menuItem = createMenuItem(processor);

        JTextComponent textComponent =
                mock(JTextComponent.class, withSettings().strictness(Strictness.LENIENT));
        given(textComponent.isEditable()).willReturn(true);
        given(textComponent.getSelectedText()).willReturn("hello");
        given(textComponent.getSelectionStart()).willReturn(0);
        given(textComponent.getSelectionEnd()).willReturn(5);
        menuItem.isEnableForComponent(textComponent);

        // When - trigger the action (selection unchanged)
        menuItem.performAction();

        // Then - replaceSelection should have been called with processed text
        verify(textComponent, timeout(1000)).replaceSelection("processed-hello");
    }

    private static EncoderOperationMenuItem createMenuItem() {
        return createMenuItem(value -> new EncodeDecodeResult("encoded-" + value));
    }

    private static EncoderOperationMenuItem createMenuItem(EncodeDecodeProcessor processor) {
        return new EncoderOperationMenuItem("Test", processor);
    }
}
