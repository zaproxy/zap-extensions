/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.addon.requester.internal.tab;

import java.awt.Component;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.function.Consumer;
import javax.swing.Icon;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JTabbedPane;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.OptionsChangedListener;
import org.parosproxy.paros.model.OptionsParam;
import org.zaproxy.addon.requester.ExtensionRequester;
import org.zaproxy.addon.requester.MessageEditorPanel;
import org.zaproxy.addon.requester.internal.tab.close.CloseTabPanel;

/** Tabbed pane (numbered, renamable) */
public abstract class NumberedRenamableTabbedPane extends JTabbedPane {

    private static final long serialVersionUID = 1L;
    private static final Component PLUS_ICON_COMPONENT = new JLabel();
    private static final Icon PLUS_ICON = ExtensionRequester.createIcon("fugue/plus.png");

    private Integer nextTabNumber = 1;

    protected NumberedRenamableTabbedPane() {
        super();
        addPlusTab();
        addMouseClickListener();
    }

    /** Adds default tab to the pane */
    public abstract void addDefaultTab();

    /** Notified about tab name change */
    protected abstract void onTabNameChanged(int index, String newName);

    /**
     * Notified editor panels about options change
     *
     * @param optionsParam Changed options
     */
    public void optionsChanged(OptionsParam optionsParam) {
        processEditorPanels(
                panel -> {
                    if (panel instanceof OptionsChangedListener) {
                        ((OptionsChangedListener) panel).optionsChanged(optionsParam);
                    }
                });
    }

    /**
     * Removes tab from tabeed pane
     *
     * @param editorPanel Editor panel to remove
     */
    public void removeTab(MessageEditorPanel editorPanel) {
        int index = indexOfComponent(editorPanel);
        int editorCount = getEditorPanelCount();

        // Select previous tab if we are at the tab before plus tab (prevent selection plus tab)
        if (editorCount > 1 && index == editorCount - 1) {
            setSelectedIndex(index - 1);
        }

        editorPanel.unload();
        editorPanel.saveConfig();

        remove(editorPanel);
    }

    /**
     * Adds requester tab to the tabbed pane
     *
     * @param tabName Tab name (title)
     * @param editorPanel Editor panel to add to the tabbed pane
     */
    public void addRequesterTab(String tabName, MessageEditorPanel editorPanel) {
        int index = Math.max(getEditorPanelCount(), 0);
        this.insertTab(tabName, null, editorPanel, null, index);
        this.setTabComponentAt(
                index, new CloseTabPanel(tabName, actionEvent -> removeTab(editorPanel)));
        this.setSelectedIndex(index);
    }

    /** Unloads all editor panels. */
    public void unload() {
        processEditorPanels(MessageEditorPanel::unload);
    }

    /**
     * Generates new tab name
     *
     * @return Tab name
     */
    protected String nextTabName() {
        return String.valueOf(nextTabNumber++);
    }

    /**
     * Processes operation using all message panels
     *
     * @param action Consumer to process the action using panel
     */
    protected void processEditorPanels(Consumer<MessageEditorPanel> action) {
        int editorPanels = getEditorPanelCount();
        for (int index = 0; index < editorPanels; ++index) {
            action.accept((MessageEditorPanel) getComponentAt(index));
        }
    }

    /**
     * Obtains count of editors (does not count PLUS tab)
     *
     * @return Editor panel count
     */
    protected int getEditorPanelCount() {
        return getTabCount() - 1;
    }

    /**
     * Handles single mouse click event
     *
     * @param event Mouse click event
     */
    protected void handleMouseSingleClicked(MouseEvent event) {
        int index = indexAtLocation(event.getX(), event.getY());
        if (index == -1) {
            return;
        }

        Component component = getComponentAt(index);
        if (component == PLUS_ICON_COMPONENT) {
            addDefaultTab();
        }
    }

    /**
     * Handles double mouse click event
     *
     * @param event Double mouse click event
     */
    protected void handleMouseDoubleClicked(MouseEvent event) {
        int index = indexAtLocation(event.getX(), event.getY());
        if (index == -1 || index == getTabCount() - 1) {
            // Index not found or points to plus tab
            return;
        }

        Component tabComponent = getTabComponentAt(index);

        String newName = showRenameDialog(tabComponent);
        if (!StringUtils.isEmpty(newName)) {
            tabComponent.setName(newName);
            onTabNameChanged(index, newName);
        }
    }

    private void addPlusTab() {
        this.addTab("", PLUS_ICON, PLUS_ICON_COMPONENT);
    }

    private void addMouseClickListener() {
        this.addMouseListener(
                new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent event) {
                        handleMouseClicked(event);
                    }

                    @Override
                    public void mouseReleased(MouseEvent event) {
                        handleMouseClicked(event);
                    }
                });
    }

    private String showRenameDialog(Component tabComponent) {
        return JOptionPane.showInputDialog(
                Constant.messages.getString("requester.tab.rename"), tabComponent.getName());
    }

    private void handleMouseClicked(MouseEvent event) {
        if (event.getClickCount() == 1) {
            handleMouseSingleClicked(event);
        } else if (event.getClickCount() == 2) {
            handleMouseDoubleClicked(event);
        }
    }
}
