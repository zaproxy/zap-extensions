/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.allinonenotes;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.Box;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JScrollPane;
import javax.swing.JToolBar;
import org.jdesktop.swingx.JXTable;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionHookView;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.HistoryReferenceEventPublisher;
import org.parosproxy.paros.model.Session;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.utils.TableExportButton;

public class ExtensionAllInOneNotes extends ExtensionAdaptor implements SessionChangedListener {

    // The name is public so that other extensions can access it
    public static final String NAME = "ExtensionAllInOneNotes";
    protected static final String PREFIX = "allinonenotes";

    /**
     * Relative path (from add-on package) to load add-on resources.
     *
     * @see Class#getResource(String)
     */
    private static final String RESOURCES = "resources";

    private static final ImageIcon ICON =
            new ImageIcon(ExtensionAllInOneNotes.class.getResource(RESOURCES + "/notepad.png"));

    private AbstractPanel statusPanel;
    private NotesTableModel notesTableModel = null;
    private JXTable notesTable = null;
    private EventConsumerImpl eventConsumerImpl;
    private ExtensionHookView hookView;
    private ExtensionHistory extHistory;
    private JToolBar toolBar;
    private JButton reload;
    private ActionListener reloadActionListener;
    private TableExportButton<JXTable> exportButton = null;

    public ExtensionAllInOneNotes() {
        super(NAME);
        setI18nPrefix(PREFIX);
    }

    @Override
    public void init() {
        super.init();
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        // As long as we're not running as a daemon
        if (getView() != null) {
            extensionHook.addSessionListener(this);
            hookView = extensionHook.getHookView();
            eventConsumerImpl = new EventConsumerImpl(getNotesTableModel());
            hookView.addStatusPanel(getStatusPanel());
            ZAP.getEventBus()
                    .registerConsumer(
                            eventConsumerImpl,
                            HistoryReferenceEventPublisher.getPublisher().getPublisherName());
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        super.unload();
        ZAP.getEventBus()
                .unregisterConsumer(
                        eventConsumerImpl,
                        HistoryReferenceEventPublisher.getPublisher().getPublisherName());
    }

    @Override
    public void sessionChanged(final Session session) {
        resetNotesTable();
    }

    @Override
    public void sessionAboutToChange(Session session) {
        // Left empty for now
    }

    @Override
    public void sessionScopeChanged(Session session) {
        // Left empty for now
    }

    @Override
    public void sessionModeChanged(Control.Mode mode) {
        // Left empty for now
    }

    private ExtensionHistory getExtensionHistory() {
        if (extHistory == null) {
            extHistory =
                    org.parosproxy.paros.control.Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionHistory.class);
        }
        return extHistory;
    }

    private AbstractPanel getStatusPanel() {

        if (statusPanel == null) {
            statusPanel = new AbstractPanel();
            statusPanel.setLayout(new BorderLayout());
            statusPanel.setName(Constant.messages.getString(PREFIX + ".panel.title"));
            statusPanel.setIcon(ICON);
            statusPanel.add(getToolBar(), BorderLayout.NORTH);
            statusPanel.add(new JScrollPane(getNotesTable()), BorderLayout.CENTER);
        }

        return statusPanel;
    }

    private NotesTableModel getNotesTableModel() {
        if (notesTableModel == null) {
            notesTableModel = new NotesTableModel();
        }
        return notesTableModel;
    }

    private JXTable getNotesTable() {
        if (notesTable == null) {
            notesTable = new JXTable();
            notesTable.setModel(getNotesTableModel());
            notesTable.setColumnSelectionAllowed(false);
            notesTable.setCellSelectionEnabled(false);
            notesTable.setRowSelectionAllowed(true);
            notesTable.setAutoCreateRowSorter(true);
            notesTable.setColumnControlVisible(true);
            notesTable
                    .getSelectionModel()
                    .addListSelectionListener(
                            new NotesTableSelectionHandler(notesTable, getExtensionHistory()));

            fillTable();
        }
        return notesTable;
    }

    private void resetNotesTable() {
        getNotesTableModel().clear();
        eventConsumerImpl.resetRowMapper();
        fillTable();
    }

    private void fillTable() {
        int lastHistoryId = getExtensionHistory().getLastHistoryId();
        int i = 0;
        while (i++ < lastHistoryId) {
            HistoryReference hr = getExtensionHistory().getHistoryReference(i);
            if (hr != null) {
                if (hr.hasNote()) {
                    eventConsumerImpl.addRowToNotesTable(i);
                }
            }
        }
    }

    private JToolBar getToolBar() {
        if (toolBar == null) {
            toolBar = new JToolBar();
            toolBar.setFloatable(false);
            toolBar.setRollover(true);
            toolBar.add(getButtonReload());
            toolBar.add(getButtonExport());
            toolBar.add(Box.createHorizontalGlue());
        }
        return toolBar;
    }

    private JButton getButtonReload() {
        if (reload == null) {
            reload = new JButton(Constant.messages.getString(PREFIX + ".reload.button"));
            reload.addActionListener(getReloadActionListener());
        }
        return reload;
    }

    private ActionListener getReloadActionListener() {
        if (reloadActionListener == null) {
            reloadActionListener =
                    new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            resetNotesTable();
                        }
                    };
        }
        return reloadActionListener;
    }

    private TableExportButton<JXTable> getButtonExport() {
        if (exportButton == null) {
            exportButton = new TableExportButton<JXTable>(getNotesTable());
        }
        return exportButton;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(PREFIX + ".desc");
    }
}
