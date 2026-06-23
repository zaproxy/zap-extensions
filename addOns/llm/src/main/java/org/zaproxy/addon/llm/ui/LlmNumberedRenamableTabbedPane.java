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

import java.awt.Component;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.swing.Icon;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JTabbedPane;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.llm.ExtensionLlm;

@SuppressWarnings("serial")
public class LlmNumberedRenamableTabbedPane extends JTabbedPane {

    private static final long serialVersionUID = 1L;
    private static final Icon PLUS_ICON = ExtensionLlm.createIcon("/resource/icon/fugue/plus.png");

    private int nextTabNumber = 1;
    private final Component hiddenComponent = new JLabel();
    private final ExtensionLlm extension;
    private Map<String, LlmChatTabPanel> taggedTabs = Collections.synchronizedMap(new HashMap<>());

    public LlmNumberedRenamableTabbedPane(ExtensionLlm extension) {
        super();
        this.extension = extension;

        addChangeListener(
                new ChangeListener() {
                    private boolean adding = false;

                    @Override
                    public void stateChanged(ChangeEvent e) {
                        LlmNumberedRenamableTabbedPane ntp =
                                (LlmNumberedRenamableTabbedPane) e.getSource();
                        if (!adding && ntp.getSelectedIndex() == ntp.getTabCount() - 1) {
                            adding = true;
                            ntp.addDefaultTab();
                            adding = false;
                        }
                    }
                });

        addMouseListener(
                new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent evt) {
                        if (evt.getClickCount() == 2) {
                            int index = indexAtLocation(evt.getX(), evt.getY());
                            if (index > -1 && index < getTabCount() - 1) {
                                Component comp = getTabComponentAt(index);
                                if (comp != null) {
                                    String newName =
                                            JOptionPane.showInputDialog(
                                                    Constant.messages.getString(
                                                            "llm.chat.tab.rename"),
                                                    comp.getName());
                                    if (!StringUtils.isEmpty(newName)) {
                                        comp.setName(newName);
                                    }
                                }
                            }
                        }
                    }
                });

        addTab("", PLUS_ICON != null ? PLUS_ICON : null, hiddenComponent);
    }

    private String nextTabName() {
        return String.valueOf(nextTabNumber++);
    }

    public void addDefaultTab() {
        addTab(nextTabName());
    }

    public LlmChatTabPanel addTab(String tabName) {
        return addTab("CHAT-" + tabName, tabName);
    }

    public LlmChatTabPanel addTab(String tag, String tabName) {
        int index = getTabCount() - 1;
        LlmChatTabPanel pane = new LlmChatTabPanel(extension, tag);
        insertTab(tabName, null, pane, null, index);
        setTabComponentAt(index, new LlmCloseTabPanel(tabName, this, tag));
        setSelectedIndex(index);
        return pane;
    }

    public LlmChatTabPanel getTaggedTab(String tag, String tabName) {
        return taggedTabs.computeIfAbsent(tag, k -> addTab(tag, tabName));
    }

    protected void unregisterTag(String tag) {
        this.taggedTabs.remove(tag);
    }

    public LlmChatTabPanel getSelectedChatPanel() {
        int index = getSelectedIndex();
        if (index >= 0 && index < getTabCount() - 1) {
            Component comp = getComponentAt(index);
            if (comp instanceof LlmChatTabPanel) {
                return (LlmChatTabPanel) comp;
            }
        }
        return null;
    }
}
