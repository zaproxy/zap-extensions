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

import java.awt.Component;
import javax.swing.text.JTextComponent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.zaproxy.addon.encoder.processors.EncodeDecodeProcessor;
import org.zaproxy.addon.encoder.processors.EncodeDecodeResult;
import org.zaproxy.zap.extension.httppanel.HttpPanelResponse;

/**
 * A leaf popup menu item that applies an {@link EncodeDecodeProcessor} to the currently selected
 * text of the invoking {@code JTextComponent} and replaces the selection with the result, keeping
 * the new text selected so that multiple operations can be chained.
 */
@SuppressWarnings("serial")
public class EncoderOperationMenuItem extends ExtensionPopupMenuItem {

    private static final Logger LOGGER = LogManager.getLogger(EncoderOperationMenuItem.class);

    private final EncodeDecodeProcessor processor;
    private volatile JTextComponent lastInvoker;

    public EncoderOperationMenuItem(String label, EncodeDecodeProcessor processor) {
        super(label);
        this.processor = processor;
        addActionListener(e -> performAction());
    }

    @Override
    public boolean isEnableForComponent(Component invoker) {
        if (isInResponseView(invoker)) {
            lastInvoker = null;
            return false;
        }
        if (invoker instanceof JTextComponent) {
            JTextComponent textComponent = (JTextComponent) invoker;
            if (!textComponent.isEditable()) {
                lastInvoker = null;
                return false;
            }
            String selectedText = textComponent.getSelectedText();
            boolean hasSelection = selectedText != null && !selectedText.isEmpty();
            setEnabled(hasSelection);
            if (hasSelection) {
                lastInvoker = textComponent;
            }
            return true;
        }

        lastInvoker = null;
        return false;
    }

    private static boolean isInResponseView(Component component) {
        for (Component c = component; c != null; c = c.getParent()) {
            if (c instanceof HttpPanelResponse) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean isSafe() {
        return true;
    }

    void performAction() {
        if (lastInvoker == null) {
            return;
        }
        final JTextComponent invoker = lastInvoker;
        final String selectedText = invoker.getSelectedText();
        if (selectedText == null || selectedText.isEmpty()) {
            return;
        }
        final int selStart = invoker.getSelectionStart();
        final int selEnd = invoker.getSelectionEnd();

        Thread thread =
                new Thread(
                        () -> {
                            try {
                                EncodeDecodeResult result = processor.process(selectedText);
                                String newText = result.getResult();
                                if (result.hasError()) {
                                    showErrorDialog(new Exception(newText));
                                } else {
                                    javax.swing.SwingUtilities.invokeLater(
                                            () ->
                                                    replaceSelectionIfUnchanged(
                                                            invoker,
                                                            newText,
                                                            selStart,
                                                            selEnd,
                                                            selectedText));
                                }
                            } catch (Exception e) {
                                LOGGER.error(
                                        "Error performing operation '{}': {}",
                                        getText(),
                                        e.getMessage(),
                                        e);
                                showErrorDialog(e);
                            }
                        },
                        "EncoderOperation-" + getText());
        thread.setDaemon(true);
        thread.start();
    }

    private static void replaceSelectionIfUnchanged(
            JTextComponent textComponent,
            String newText,
            int expectedStart,
            int expectedEnd,
            String expectedText) {
        try {
            int start = textComponent.getSelectionStart();
            int end = textComponent.getSelectionEnd();
            if (start != expectedStart
                    || end != expectedEnd
                    || !expectedText.equals(textComponent.getSelectedText())) {
                return;
            }
            textComponent.replaceSelection(newText);
            textComponent.setSelectionStart(start);
            textComponent.setSelectionEnd(start + newText.length());
        } catch (RuntimeException e) {
            LOGGER.warn("Could not replace the selected text", e);
        }
    }

    private void showErrorDialog(Exception e) {
        javax.swing.SwingUtilities.invokeLater(
                () ->
                        org.parosproxy.paros.view.View.getSingleton()
                                .showWarningDialog(
                                        Constant.messages.getString(
                                                "encoder.popup.operation.error",
                                                getText(),
                                                e.getMessage() == null
                                                        ? e.toString()
                                                        : e.getMessage())));
    }
}
