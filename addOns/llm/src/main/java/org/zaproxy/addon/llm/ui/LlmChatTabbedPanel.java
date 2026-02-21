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
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.Objects;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.zaproxy.addon.llm.ExtensionLlm;
import org.zaproxy.zap.extension.help.ExtensionHelp;
import org.zaproxy.zap.utils.DisplayUtils;

@SuppressWarnings("serial")
public class LlmChatTabbedPanel extends AbstractPanel implements LlmChatPanelProvider {

    private static final long serialVersionUID = 1L;
    private static final String PLUS_TITLE = "+";

    private final ExtensionLlm extension;
    private final JTabbedPane tabbedPane;
    private int nextTabNumber;

    public LlmChatTabbedPanel(ExtensionLlm extension) {
        this.extension = Objects.requireNonNull(extension);
        this.nextTabNumber = 1;

        setName(Constant.messages.getString("llm.chat.panel.title"));
        setIcon(
                DisplayUtils.getScaledIcon(
                        getClass().getResource("/org/zaproxy/addon/llm/resources/agent.png")));
        setLayout(new BorderLayout());

        tabbedPane = new JTabbedPane();
        tabbedPane.addChangeListener(
                e -> {
                    int idx = tabbedPane.getSelectedIndex();
                    if (idx >= 0 && isPlusTabIndex(idx)) {
                        addNewChatTabAndSelect();
                    }
                });

        add(tabbedPane, BorderLayout.CENTER);

        addNewChatTabAndSelect();
        addPlusTab();

        ExtensionHelp.enableHelpKey(this, "addon.llm.chat");
    }

    @Override
    public void focusLlmChat() {
        setTabFocus();
        ensureNonPlusTabSelected();
    }

    @Override
    public LlmChatPanel getActiveChatPanel() {
        ensureNonPlusTabSelected();
        Component c = tabbedPane.getSelectedComponent();
        if (c instanceof LlmChatPanel chatPanel) {
            return chatPanel;
        }
        // Fallback: first chat tab.
        for (int i = 0; i < tabbedPane.getTabCount(); i++) {
            Component comp = tabbedPane.getComponentAt(i);
            if (comp instanceof LlmChatPanel chat) {
                return chat;
            }
        }
        return null;
    }

    @Override
    public LlmChatPanel openNewChatTab() {
        ensureNonPlusTabSelected();
        return addNewChatTabAndSelect();
    }

    private void ensureNonPlusTabSelected() {
        int idx = tabbedPane.getSelectedIndex();
        if (idx >= 0 && isPlusTabIndex(idx)) {
            addNewChatTabAndSelect();
        }
        if (tabbedPane.getSelectedIndex() < 0 && tabbedPane.getTabCount() > 0) {
            tabbedPane.setSelectedIndex(0);
        }
    }

    private void addPlusTab() {
        JPanel hidden = new JPanel();
        hidden.setPreferredSize(new Dimension(0, 0));
        tabbedPane.addTab(PLUS_TITLE, hidden);
        tabbedPane.setEnabledAt(tabbedPane.getTabCount() - 1, true);
    }

    private boolean isPlusTabIndex(int idx) {
        return idx == tabbedPane.getTabCount() - 1 && PLUS_TITLE.equals(tabbedPane.getTitleAt(idx));
    }

    private LlmChatPanel addNewChatTabAndSelect() {
        int plusIndex = tabbedPane.getTabCount() - 1;
        if (plusIndex < 0) {
            plusIndex = 0;
        }
        if (plusIndex >= 0 && isPlusTabIndex(plusIndex)) {
            // Insert before the plus tab.
            int insertAt = plusIndex;
            LlmChatPanel chatPanel = new LlmChatPanel(extension);
            String title = Integer.toString(nextTabNumber++);
            tabbedPane.insertTab(title, null, chatPanel, null, insertAt);
            tabbedPane.setTabComponentAt(insertAt, createTabHeader(title, chatPanel));
            tabbedPane.setSelectedIndex(insertAt);
            SwingUtilities.invokeLater(chatPanel::requestFocusInWindow);
            return chatPanel;
        }

        // No plus tab yet, append.
        LlmChatPanel chatPanel = new LlmChatPanel(extension);
        String title = Integer.toString(nextTabNumber++);
        tabbedPane.addTab(title, chatPanel);
        int idx = tabbedPane.getTabCount() - 1;
        tabbedPane.setTabComponentAt(idx, createTabHeader(title, chatPanel));
        tabbedPane.setSelectedIndex(idx);
        SwingUtilities.invokeLater(chatPanel::requestFocusInWindow);
        return chatPanel;
    }

    private Component createTabHeader(String title, Component tabComponent) {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        panel.setOpaque(false);
        panel.setBorder(BorderFactory.createEmptyBorder(2, 2, 2, 2));

        JLabel label = new JLabel(title);
        panel.add(label);

        JButton close = new JButton("×");
        close.setFocusable(false);
        close.setBorder(BorderFactory.createEmptyBorder());
        close.setContentAreaFilled(false);
        close.setOpaque(false);
        close.setToolTipText(Constant.messages.getString("llm.chat.panel.tab.close"));
        close.addActionListener(e -> closeTab(tabComponent));

        // Middle-click anywhere on the tab header closes it (Requester-like).
        panel.addMouseListener(
                new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e) {
                        if (SwingUtilities.isMiddleMouseButton(e)) {
                            closeTab(tabComponent);
                        }
                    }
                });

        panel.add(close);
        return panel;
    }

    private void closeTab(Component tabComponent) {
        int idx = tabbedPane.indexOfComponent(tabComponent);
        if (idx < 0) {
            return;
        }

        // Don't allow closing the plus tab.
        if (isPlusTabIndex(idx)) {
            return;
        }

        // Keep at least one chat tab open.
        if (countChatTabs() <= 1) {
            return;
        }

        tabbedPane.removeTabAt(idx);
        ensureNonPlusTabSelected();
    }

    private int countChatTabs() {
        int count = 0;
        for (int i = 0; i < tabbedPane.getTabCount(); i++) {
            if (!isPlusTabIndex(i) && tabbedPane.getComponentAt(i) instanceof LlmChatPanel) {
                count++;
            }
        }
        return count;
    }
}
