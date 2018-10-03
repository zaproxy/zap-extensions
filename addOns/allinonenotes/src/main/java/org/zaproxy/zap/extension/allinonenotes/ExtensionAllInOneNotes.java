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

import java.awt.CardLayout;
import java.net.MalformedURLException;
import java.net.URL;
import javax.swing.BoxLayout;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
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
import org.zaproxy.zap.view.ZapMenuItem;

public class ExtensionAllInOneNotes extends ExtensionAdaptor implements SessionChangedListener {

    private ZapMenuItem menuReload;
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
    protected static JXTable notesTable = new JXTable();
    private static EventConsumerImpl eventConsumerImpl;

    private static ExtensionHookView hookView;

    private static JButton reload;
    private static TableExportButton<JXTable> exportButton = null;

    public ExtensionAllInOneNotes() {
        super(NAME);
        setI18nPrefix(PREFIX);
    }

    @Override
    public void init() {
        super.init();
        reload = new JButton(Constant.messages.getString(PREFIX + ".reload.button"));
        eventConsumerImpl = new EventConsumerImpl();
        ZAP.getEventBus()
                .registerConsumer(
                        eventConsumerImpl,
                        HistoryReferenceEventPublisher.getPublisher().getPublisherName());
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        extensionHook.addSessionListener(this);
        // As long as we're not running as a daemon
        if (getView() != null) {

            extensionHook.getHookMenu().addToolsMenuItem(getMenuReload());
            hookView = extensionHook.getHookView();
            hookView.addStatusPanel(getStatusPanel());

            // TODO: supplement or remove reload with events to dynamicaly populate notes
            reload.addActionListener(
                    l -> {
                        hookView.addStatusPanel(getStatusPanel());
                    });
        }
    }

    @Override
    public boolean canUnload() {
        // The extension can be dynamically unloaded, all resources used/added can be freed/removed
        // from core.
        return true;
    }

    @Override
    public void unload() {
        super.unload();
        // Unloading the event consumer
        ZAP.getEventBus()
                .unregisterConsumer(
                        eventConsumerImpl,
                        HistoryReferenceEventPublisher.getPublisher().getPublisherName());
    }

    @Override
    public void sessionChanged(final Session session) {
        // session changed - extension should basically act as if "Reload" has been called and
        // re-build the status panel
        hookView.addStatusPanel(getStatusPanel());
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

    private AbstractPanel getStatusPanel() {

        NotesTableModel notesTableModel = new NotesTableModel();
        notesTable.setModel(notesTableModel);

        ExtensionHistory extHist = org.parosproxy.paros.control.Control.getSingleton().getExtensionLoader()
                .getExtension(ExtensionHistory.class);

        if (extHist != null) {

            int LastHistoryId = extHist.getLastHistoryId();

            int i = 0;
            while (i++ < LastHistoryId) {
                HistoryReference hr = extHist.getHistoryReference(i);
                if (hr != null) {
                    if (hr.hasNote()) {
                        eventConsumerImpl.addRowToNotesTable(i);
                    }
                }
            }
        }

        notesTable.setColumnSelectionAllowed(false);
        notesTable.setCellSelectionEnabled(false);
        notesTable.setRowSelectionAllowed(true);
        notesTable.setAutoCreateRowSorter(true);
        notesTable.setColumnControlVisible(true);
        notesTable
                .getSelectionModel()
                .addListSelectionListener(new NotesTableSelectionHandler(notesTable, extHist));

        exportButton = new TableExportButton<>(notesTable);

        JPanel buttonContainer = new JPanel();
        buttonContainer.setLayout(new BoxLayout(buttonContainer, BoxLayout.X_AXIS));
        buttonContainer.add(reload);
        buttonContainer.add(exportButton);

        JPanel pContainer = new JPanel();
        pContainer.setLayout(new BoxLayout(pContainer, BoxLayout.Y_AXIS));
        pContainer.add(buttonContainer);
        pContainer.add(new JScrollPane(notesTable));

        if (statusPanel != null) {
            statusPanel.removeAll();
            eventConsumerImpl.resetRowMapper();
            statusPanel.add(pContainer);
        } else {

            statusPanel = new AbstractPanel();
            statusPanel.setLayout(new CardLayout());
            statusPanel.setName(Constant.messages.getString(PREFIX + ".panel.title"));
            statusPanel.setIcon(ICON);

            statusPanel.add(pContainer);
        }

        return statusPanel;
    }

    private ZapMenuItem getMenuReload() {
        if (menuReload == null) {
            menuReload = new ZapMenuItem(PREFIX + ".topmenu.tools.reload");

            menuReload.addActionListener(
                    ae -> {
                        hookView.addStatusPanel(getStatusPanel());
                    });
        }
        return menuReload;
    }

    @Override
    public String getAuthor() {
        return "David Vassallo";
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(PREFIX + ".desc");
    }

    @Override
    public URL getURL() {
        try {
            return new URL(Constant.ZAP_EXTENSIONS_PAGE);
        } catch (MalformedURLException e) {
            return null;
        }
    }
}
