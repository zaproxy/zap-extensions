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
package org.zaproxy.addon.llm.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.border.Border;
import javax.swing.border.EmptyBorder;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.llm.ExtensionLlm;
import org.zaproxy.addon.llm.services.LlmCommunicationService;
import org.zaproxy.zap.extension.help.ExtensionHelp;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.utils.ZapTextArea;

@SuppressWarnings("serial")
public class LlmChatPanel extends AbstractPanel {

    private static final long serialVersionUID = 1L;

    private ExtensionLlm extension;
    private ZapTextArea messageArea;
    private JPanel inputPanel;
    private ZapTextArea inputArea;
    private JButton sendButton;
    private JSplitPane splitPane;
    private boolean isProcessing = false;

    public LlmChatPanel(ExtensionLlm extension) {
        super();
        this.extension = extension;

        setName(Constant.messages.getString("llm.chat.panel.title"));
        setIcon(
                DisplayUtils.getScaledIcon(
                        getClass().getResource("/org/zaproxy/addon/llm/resources/agent.png")));
        setLayout(new BorderLayout());

        // Initialize message area
        messageArea = new ZapTextArea();
        messageArea.setEditable(false);
        messageArea.setLineWrap(true);
        messageArea.setWrapStyleWord(true);
        messageArea.setFont(FontUtils.getFont("Dialog"));
        messageArea.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        messageArea.setText(Constant.messages.getString("llm.chat.panel.welcome"));
        updateTextAreaColors(messageArea);

        // Initialize message scroll pane
        JScrollPane messageScrollPane = new JScrollPane();
        messageScrollPane.setViewportView(messageArea);
        messageScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        messageScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        messageScrollPane.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Initialize input field (TextArea)
        inputArea = new ZapTextArea();
        inputArea.setFont(FontUtils.getFont("Dialog"));
        inputArea.setLineWrap(true);
        inputArea.setWrapStyleWord(true);
        inputArea.setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10));
        updateTextAreaColors(inputArea);
        inputArea.addKeyListener(
                new KeyAdapter() {
                    @Override
                    public void keyPressed(KeyEvent e) {
                        if (e.getKeyCode() == KeyEvent.VK_ENTER && e.isControlDown()) {
                            e.consume();
                            sendMessage();
                        }
                    }
                });

        // Initialize input scroll pane
        JScrollPane inputScrollPane = new JScrollPane(inputArea);
        inputScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        inputScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        inputScrollPane.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));

        // Initialize send button
        sendButton = new JButton(Constant.messages.getString("llm.chat.panel.send"));
        sendButton.setPreferredSize(new Dimension(80, 35));
        sendButton.setMaximumSize(new Dimension(80, 35));
        sendButton.addActionListener(e -> sendMessage());

        // Wrap button in panel to prevent vertical expansion
        JPanel buttonPanel = new JPanel(new BorderLayout());
        buttonPanel.add(sendButton, BorderLayout.NORTH);

        // Initialize input container
        JPanel inputContainer = new JPanel(new BorderLayout(10, 0));
        inputContainer.add(inputScrollPane, BorderLayout.CENTER);
        inputContainer.add(buttonPanel, BorderLayout.EAST);

        // Initialize input panel
        inputPanel = new JPanel(new BorderLayout());
        inputPanel.add(inputContainer, BorderLayout.CENTER);
        updateInputPanelBorder();

        // Initialize split pane with resizable divider
        splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, messageScrollPane, inputPanel);
        splitPane.setResizeWeight(0.75); // Give 75% to message area, 25% to input
        splitPane.setOneTouchExpandable(true);
        splitPane.setContinuousLayout(true);
        splitPane.setDividerSize(8);

        add(splitPane, BorderLayout.CENTER);

        ExtensionHelp.enableHelpKey(this, "addon.llm.chat");
    }

    private Border getInputPanelTopBorder() {
        Color borderColor = UIManager.getColor("Separator.foreground");
        if (borderColor == null) {
            borderColor = UIManager.getColor("controlShadow");
        }
        if (borderColor == null) {
            borderColor = Color.LIGHT_GRAY;
        }
        return BorderFactory.createMatteBorder(1, 0, 0, 0, borderColor);
    }

    private void updateInputPanelBorder() {
        if (inputPanel != null) {
            inputPanel.setBorder(
                    BorderFactory.createCompoundBorder(
                            getInputPanelTopBorder(), new EmptyBorder(10, 10, 10, 10)));
        }
    }

    private void updateTextAreaColors(ZapTextArea txt) {
        if (txt != null) {
            Color bgColor = UIManager.getColor("TextArea.background");
            Color fgColor = UIManager.getColor("TextArea.foreground");
            if (bgColor != null) {
                txt.setBackground(bgColor);
            }
            if (fgColor != null) {
                txt.setForeground(fgColor);
            }
        }
    }

    private void sendMessage() {
        String message = inputArea.getText().trim();
        if (message.isEmpty() || isProcessing) {
            return;
        }

        if (!extension.isConfigured()) {
            appendMessage(Constant.messages.getString("llm.chat.panel.error.notconfigured"));
            return;
        }

        inputArea.setText("");
        inputArea.setEnabled(false);
        sendButton.setEnabled(false);
        isProcessing = true;

        appendMessage(
                Constant.messages.getString(
                        "llm.chat.panel.message.format",
                        Constant.messages.getString("llm.chat.panel.user.label"),
                        message));

        // Send message to LLM in background thread
        Thread chatThread =
                new Thread(
                        () -> {
                            try {
                                LlmCommunicationService service =
                                        extension.getCommunicationService("chat");
                                if (service == null) {
                                    appendFormattedMessageLater(
                                            "llm.chat.panel.error.service", null);
                                    return;
                                }
                                appendFormattedMessageLater(
                                        "llm.chat.panel.assistant.label", service.chat(message));

                            } catch (Exception e) {
                                appendFormattedMessageLater(
                                        "llm.chat.panel.assistant.label", e.getMessage());
                            }
                        },
                        "ZAP-LLM-Chat");
        chatThread.start();
    }

    private void appendFormattedMessageLater(String key, String message) {
        SwingUtilities.invokeLater(
                () -> {
                    if (message != null) {
                        appendMessage(
                                Constant.messages.getString(
                                        "llm.chat.panel.message.format",
                                        Constant.messages.getString(key),
                                        message));

                    } else {
                        appendMessage(Constant.messages.getString(key));
                    }
                    resetInput();
                });
    }

    private void appendMessage(String message) {
        String currentText = messageArea.getText();
        if (currentText.isEmpty()
                || currentText.equals(Constant.messages.getString("llm.chat.panel.welcome"))) {
            messageArea.setText(message);
        } else {
            messageArea.append("\n\n" + message);
        }

        // Auto-scroll to bottom
        messageArea.setCaretPosition(messageArea.getDocument().getLength());
    }

    private void resetInput() {
        inputArea.setEnabled(true);
        sendButton.setEnabled(true);
        isProcessing = false;
        inputArea.requestFocusInWindow();
    }

    public void appendAlertToInput(Alert alert) {
        StringBuilder sb = new StringBuilder();
        sb.append(
                        Constant.messages.getString(
                                "llm.chat.append.alert.format",
                                Constant.messages.getString("llm.chat.append.alert.label"),
                                alert.getName()))
                .append("\n");
        int risk = alert.getRisk();
        if (risk >= 0 && risk < Alert.MSG_RISK.length) {
            sb.append(
                            Constant.messages.getString(
                                    "llm.chat.append.alert.format",
                                    Constant.messages.getString("llm.chat.append.alert.risk"),
                                    Alert.MSG_RISK[risk]))
                    .append("\n");
        }
        int confidence = alert.getConfidence();
        if (confidence >= 0 && confidence < Alert.MSG_CONFIDENCE.length) {
            sb.append(
                            Constant.messages.getString(
                                    "llm.chat.append.alert.format",
                                    Constant.messages.getString("llm.chat.append.alert.confidence"),
                                    Alert.MSG_CONFIDENCE[confidence]))
                    .append("\n");
        }
        sb.append(
                        Constant.messages.getString(
                                "llm.chat.append.alert.format",
                                Constant.messages.getString("llm.chat.append.alert.description"),
                                alert.getDescription()))
                .append("\n");
        if (alert.getEvidence() != null && !alert.getEvidence().isEmpty()) {
            sb.append(
                            Constant.messages.getString(
                                    "llm.chat.append.alert.format",
                                    Constant.messages.getString("llm.chat.append.alert.evidence"),
                                    alert.getEvidence()))
                    .append("\n");
        }
        if (alert.getOtherInfo() != null && !alert.getOtherInfo().isEmpty()) {
            sb.append(
                            Constant.messages.getString(
                                    "llm.chat.append.alert.format",
                                    Constant.messages.getString("llm.chat.append.alert.otherinfo"),
                                    alert.getOtherInfo()))
                    .append("\n");
        }
        if (alert.getUri() != null) {
            sb.append(
                            Constant.messages.getString(
                                    "llm.chat.append.alert.format",
                                    Constant.messages.getString("llm.chat.append.alert.uri"),
                                    alert.getUri()))
                    .append("\n");
        }

        String currentText = inputArea.getText();
        if (!currentText.isEmpty() && !currentText.endsWith("\n")) {
            inputArea.append("\n\n");
        } else if (!currentText.isEmpty()) {
            inputArea.append("\n");
        }
        inputArea.append(sb.toString());

        // Switch to chat panel and set cursor to end
        setTabFocus();
        SwingUtilities.invokeLater(
                () -> {
                    inputArea.setCaretPosition(inputArea.getDocument().getLength());
                    inputArea.requestFocusInWindow();
                });
    }

    public void appendHttpMessageToInput(
            HttpMessage httpMessage, boolean includeRequest, boolean includeResponse) {
        StringBuilder sb = new StringBuilder();
        sb.append(
                        Constant.messages.getString(
                                "llm.chat.append.alert.format",
                                Constant.messages.getString("llm.chat.append.http.message.label"),
                                httpMessage.getRequestHeader().getURI()))
                .append("\n\n");

        if (includeRequest) {
            sb.append(Constant.messages.getString("llm.chat.append.http.request.header"))
                    .append("\n");
            sb.append(httpMessage.getRequestHeader().toString());
            if (httpMessage.getRequestBody() != null && httpMessage.getRequestBody().length() > 0) {
                sb.append("\n");
                sb.append(httpMessage.getRequestBody().toString());
            }
            sb.append("\n\n");
        }

        if (includeResponse && httpMessage.getResponseHeader() != null) {
            sb.append(Constant.messages.getString("llm.chat.append.http.response.header"))
                    .append("\n");
            sb.append(httpMessage.getResponseHeader().toString());
            if (httpMessage.getResponseBody() != null
                    && httpMessage.getResponseBody().length() > 0) {
                sb.append("\n");
                sb.append(httpMessage.getResponseBody().toString());
            }
            sb.append("\n");
        }

        String currentText = inputArea.getText();
        if (!currentText.isEmpty() && !currentText.endsWith("\n")) {
            inputArea.append("\n\n");
        } else if (!currentText.isEmpty()) {
            inputArea.append("\n");
        }
        inputArea.append(sb.toString());

        // Switch to chat panel and set cursor to end
        setTabFocus();
        SwingUtilities.invokeLater(
                () -> {
                    inputArea.setCaretPosition(inputArea.getDocument().getLength());
                    inputArea.requestFocusInWindow();
                });
    }

    @Override
    public void updateUI() {
        super.updateUI();
        updateTextAreaColors(messageArea);
        updateTextAreaColors(inputArea);
        updateInputPanelBorder();
    }
}
