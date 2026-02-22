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
import java.awt.FlowLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.URL;
import java.util.Objects;
import javax.swing.Icon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.zaproxy.addon.llm.ExtensionLlm;
import org.zaproxy.zap.extension.help.ExtensionHelp;
import org.zaproxy.zap.utils.DisplayUtils;

@SuppressWarnings("serial")
public class LlmChatTabbedPanel extends AbstractPanel implements LlmChatPanelProvider {

    private static final long serialVersionUID = 1L;
    private static final Icon PLUS_ICON = createFugueIcon("plus.png");
    private static final Icon CLOSE_GREY_ICON = createFugueIcon("cross-small-grey.png");
    private static final Icon CLOSE_RED_ICON = createFugueIcon("cross-small-red.png");

    private final ExtensionLlm extension;
    private final JTabbedPane tabbedPane;
    private final Component plusTabComponent;
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
        tabbedPane.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);
        plusTabComponent = new JLabel();
        tabbedPane.addChangeListener(e -> handlePlusTabSelection());

        add(tabbedPane, BorderLayout.CENTER);

        addPlusTab();
        addNewChatTabAndSelect();

        ExtensionHelp.enableHelpKey(this, "addon.llm.chat");
    }

    private static Icon createFugueIcon(String filename) {
        URL url =
                LlmChatTabbedPanel.class.getResource(
                        "/org/zaproxy/addon/llm/images/fugue/" + filename);
        return url != null ? DisplayUtils.getScaledIcon(url) : null;
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
            // Avoid creating tabs on focus. Select the first chat tab instead.
            if (tabbedPane.getTabCount() > 1) {
                tabbedPane.setSelectedIndex(0);
            }
        }
        if (tabbedPane.getSelectedIndex() < 0 && tabbedPane.getTabCount() > 0) {
            tabbedPane.setSelectedIndex(0);
        }
    }

    private void addPlusTab() {
        tabbedPane.addTab("", PLUS_ICON, plusTabComponent);
    }

    private boolean isPlusTabIndex(int idx) {
        return idx == tabbedPane.getTabCount() - 1
                && tabbedPane.getComponentAt(idx) == plusTabComponent;
    }

    private boolean addingTab;

    private void handlePlusTabSelection() {
        if (addingTab) {
            return;
        }

        int idx = tabbedPane.getSelectedIndex();
        if (idx >= 0 && isPlusTabIndex(idx)) {
            addingTab = true;
            try {
                addNewChatTabAndSelect();
            } finally {
                addingTab = false;
            }
        }
    }

    private LlmChatPanel addNewChatTabAndSelect() {
        int insertAt = Math.max(0, tabbedPane.getTabCount() - 1);
        LlmChatPanel chatPanel = new LlmChatPanel(extension);
        String title = Integer.toString(nextTabNumber++);
        tabbedPane.insertTab(title, null, chatPanel, null, insertAt);
        tabbedPane.setTabComponentAt(insertAt, createTabHeader(title, chatPanel));
        tabbedPane.setSelectedIndex(insertAt);
        SwingUtilities.invokeLater(chatPanel::requestFocusInWindow);
        return chatPanel;
    }

    private Component createTabHeader(String title, Component tabComponent) {
        ClosableTabHeader panel = new ClosableTabHeader(title);
        installTabSelectionAndRenameHandlers(panel, panel.label, tabComponent);
        panel.close.addActionListener(e -> closeTab(tabComponent));
        return panel;
    }

    private void installTabSelectionAndRenameHandlers(
            Component tabHeader, Component tabLabel, Component tabComponent) {
        MouseAdapter adapter =
                new MouseAdapter() {
                    @Override
                    public void mousePressed(MouseEvent e) {
                        if (!SwingUtilities.isLeftMouseButton(e)) {
                            return;
                        }
                        int idx = tabbedPane.indexOfComponent(tabComponent);
                        if (idx >= 0) {
                            tabbedPane.setSelectedIndex(idx);
                        }
                    }

                    @Override
                    public void mouseClicked(MouseEvent e) {
                        if (e.getClickCount() != 2 || !SwingUtilities.isLeftMouseButton(e)) {
                            return;
                        }
                        int idx = tabbedPane.indexOfComponent(tabComponent);
                        maybeRenameTabAt(idx);
                    }
                };
        tabHeader.addMouseListener(adapter);
        tabLabel.addMouseListener(adapter);
    }

    private void maybeRenameTabAt(int idx) {
        if (idx < 0 || idx >= tabbedPane.getTabCount() || isPlusTabIndex(idx)) {
            return;
        }
        Component tabComponent = tabbedPane.getComponentAt(idx);
        if (!(tabComponent instanceof LlmChatPanel)) {
            return;
        }

        String currentName = tabbedPane.getTitleAt(idx);
        Component header = tabbedPane.getTabComponentAt(idx);
        if (header != null && StringUtils.isNotBlank(header.getName())) {
            currentName = header.getName();
        }

        String newName =
                JOptionPane.showInputDialog(
                        this,
                        Constant.messages.getString("llm.chat.panel.tab.rename"),
                        StringUtils.defaultString(currentName));
        if (StringUtils.isBlank(newName)) {
            return;
        }

        String finalName = newName.trim();
        tabbedPane.setTitleAt(idx, finalName);
        if (header != null) {
            header.setName(finalName);
        }
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

        // If closing the last chat tab, select the previous one first.
        if (tabbedPane.getTabCount() > 2 && idx == tabbedPane.getTabCount() - 2) {
            tabbedPane.setSelectedIndex(Math.max(0, idx - 1));
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

    private static final class ClosableTabHeader extends JPanel {

        private static final long serialVersionUID = 1L;

        private final JLabel label;
        private final JButton close;

        private ClosableTabHeader(String title) {
            super(new FlowLayout(FlowLayout.LEFT, 6, 0));
            setOpaque(false);
            setBorder(new EmptyBorder(2, 2, 2, 2));

            label = new JLabel(title);
            add(label);

            close = new JButton(CLOSE_GREY_ICON == null ? "×" : null);
            close.setFocusable(false);
            close.setContentAreaFilled(false);
            close.setOpaque(false);
            close.setBorder(new EmptyBorder(0, 6, 0, 0));
            close.setBorderPainted(false);
            close.setToolTipText(Constant.messages.getString("all.button.close"));
            if (CLOSE_GREY_ICON != null) {
                close.setIcon(CLOSE_GREY_ICON);
            }
            if (CLOSE_RED_ICON != null) {
                close.setRolloverIcon(CLOSE_RED_ICON);
                close.setRolloverEnabled(true);
            }

            add(close);
            setName(title);
        }

        @Override
        public void setName(String name) {
            super.setName(name);
            label.setText(name);
        }

        @Override
        public String getName() {
            return label.getText();
        }
    }
}
