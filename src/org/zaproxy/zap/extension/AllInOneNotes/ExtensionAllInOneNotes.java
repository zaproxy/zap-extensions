/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0 
 *   
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. 
 */
package org.zaproxy.zap.extension.AllInOneNotes;

import java.awt.CardLayout;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;

import javax.swing.*;

import org.apache.log4j.Logger;
import org.jdesktop.swingx.JXTable;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionHookView;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.zaproxy.zap.utils.TableExportButton;
import org.zaproxy.zap.view.ZapMenuItem;

public class ExtensionAllInOneNotes extends ExtensionAdaptor {

    private ZapMenuItem menuExample;
    // The name is public so that other extensions can access it
    public static final String NAME = "ExtensionAllInOneNotes";

    // The i18n prefix, by default the package name - defined in one place to make it easier
    // to copy and change this example
    protected static final String PREFIX = "allInOneNotes";

    /**
     * Relative path (from add-on package) to load add-on resources.
     * 
     * @see Class#getResource(String)
     */
    private static final String RESOURCES = "resources";

    private static final ImageIcon ICON = new ImageIcon(
            ExtensionAllInOneNotes.class.getResource(RESOURCES + "/notepad.png"));

    private AbstractPanel statusPanel;
    private ListSelectionModel tableSelectionModel;

    private static final Logger LOGGER = Logger.getLogger(ExtensionAllInOneNotes.class);
    private static ExtensionHookView hookView;

    private static JButton reload = new JButton("Reload Notes");
    private static TableExportButton<JXTable> exportButton = null;


    public ExtensionAllInOneNotes() {
        super(NAME);
        setI18nPrefix(PREFIX);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        // As long as we're not running as a daemon
        if (getView() != null) {

            reload.addActionListener(l -> {
                hookView.addStatusPanel(getStatusPanel());
            });

            extensionHook.getHookMenu().addToolsMenuItem(getMenuExample());
            hookView = extensionHook.getHookView();
            hookView.addStatusPanel(getStatusPanel());
        }
    }

    @Override
    public boolean canUnload() {
        // The extension can be dynamically unloaded, all resources used/added can be freed/removed from core.
        return true;
    }

    @Override
    public void unload() {
        super.unload();

        // In this example it's not necessary to override the method, as there's nothing to unload
        // manually, the components added through the class ExtensionHook (in hook(ExtensionHook))
        // are automatically removed by the base unload() method.
        // If you use/add other components through other methods you might need to free/remove them
        // here (if the extension declares that can be unloaded, see above method).
    }

    private AbstractPanel getStatusPanel() {

        ExtensionHistory extHist = (ExtensionHistory) org.parosproxy.paros.control.Control.getSingleton().
                getExtensionLoader().getExtension(ExtensionHistory.NAME);


        ArrayList<String[]> notes = new ArrayList<>();

        if (extHist != null) {

            int LastHistoryId = extHist.getLastHistoryId();

            int i=0;
            while (i++ < LastHistoryId) {
                HistoryReference hr = extHist.getHistoryReference(i);
                if (hr != null) {
                    if (hr.hasNote()) {
                        try {
                            String note = hr.getHttpMessage().getNote();
                            String[] tableRow = {String.valueOf(i), note};
                            notes.add(tableRow);
                        } catch (HttpMalformedHeaderException e) {
                        } catch (DatabaseException e) {
                            e.printStackTrace();
                        }
                    }
                }
            }
        }


        JXTable notesTable = new JXTable(new NotesTableModel(notes));
        notesTable.setColumnSelectionAllowed(false);
        notesTable.setCellSelectionEnabled(false);
        notesTable.setRowSelectionAllowed(true);
        notesTable.setAutoCreateRowSorter(true);
        notesTable.setColumnControlVisible(true);

        exportButton = new TableExportButton<>(notesTable);

        tableSelectionModel = notesTable.getSelectionModel();
        tableSelectionModel.addListSelectionListener(new NotesTableSelectionHandler(notesTable, extHist));

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

    private ZapMenuItem getMenuExample() {
        if (menuExample == null) {
            menuExample = new ZapMenuItem(PREFIX + ".topmenu.tools.reload");

            menuExample.addActionListener( ae -> {
                hookView.addStatusPanel(getStatusPanel());
            });
        }
        return menuExample;
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
