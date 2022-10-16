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

import org.zaproxy.addon.requester.MessageEditorPanel;
import org.zaproxy.addon.requester.db.RequesterTabRecord;
import org.zaproxy.addon.requester.db.RequesterTabStorage;
import org.zaproxy.addon.requester.internal.tab.editor.RequestTabHttpEditorWrapper;
import org.zaproxy.addon.requester.util.RequesterMessageConverter;
import org.zaproxy.addon.requester.util.RequesterUtil;
import org.zaproxy.zap.extension.httppanel.Message;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Requester tabbed pane
 */
public class RequesterNumberedRenamableTabbedPane extends NumberedRenamableTabbedPane {

    private static final long serialVersionUID = 1L;

    private final RequesterTabStorage tabStorage;
    private final Map<MessageEditorPanel, RequesterTabRecord> editorPanelMap = new HashMap<>();

    public RequesterNumberedRenamableTabbedPane(RequesterTabStorage tabStorage) {
        super();
        this.tabStorage = tabStorage;
        initializeTabs();
    }

    /**
     * Creates new tab for given message
     * @param message Message to be added
     */
    public void newRequester(Message message) {
        RequesterTabRecord tabRecord = tabStorage.createNewTab(
                nextTabName(),
                getEditorPanelCount(),
                RequesterMessageConverter.toJsonObject(message),
                message.getType());

        createEditorPanel(message, tabRecord);
    }

    @Override
    protected void onTabNameChanged(int index, String newName) {
        MessageEditorPanel requestPane = (MessageEditorPanel) getComponentAt(index);
        RequesterTabRecord tabRecord = editorPanelMap.get(requestPane);
        tabRecord.setName(newName);
        tabStorage.updateTabName(tabRecord);
    }

    @Override
    public void removeTab(MessageEditorPanel tabComponent) {
        super.removeTab(tabComponent);

        RequesterTabRecord tabRecord = editorPanelMap.remove(tabComponent);
        tabStorage.deleteTab(tabRecord);

        // Recalculate indexes for all panels from current to the last
        int editorPanels = getEditorPanelCount();
        for (int index = tabRecord.getIndex(); index < editorPanels; ++index) {
            MessageEditorPanel editorPanel = (MessageEditorPanel) getComponentAt(index);
            RequesterTabRecord panelRecord = editorPanelMap.get(editorPanel);
            panelRecord.setIndex(index);
            tabStorage.updateTabIndex(panelRecord);
        }
    }

    @Override
    public void addDefaultTab() {
        Message message = RequesterUtil.createDefaultHttpMessage();
        newRequester(message);
    }

    private void createEditorPanel(Message message, RequesterTabRecord tabRecord) {
        RequestTabHttpEditorWrapper editorPanel = new RequestTabHttpEditorWrapper(tabStorage, tabRecord);
        editorPanelMap.put(editorPanel, tabRecord);
        editorPanel.setUpdateTabRecord(false);
        editorPanel.setMessage(message);
        editorPanel.setUpdateTabRecord(true);
        addRequesterTab(tabRecord.getName(), editorPanel);
    }

    private void initializeTabs() {
        List<RequesterTabRecord> tabRecords = tabStorage.getTabs();
        if (tabRecords.isEmpty()) {
            addDefaultTab();
            return;
        }

        for (RequesterTabRecord tabRecord : tabRecords) {
            Message message = RequesterMessageConverter.toMessage(tabRecord.getMessage(), tabRecord.getMessageType());
            createEditorPanel(message, tabRecord);
        }
    }

}
