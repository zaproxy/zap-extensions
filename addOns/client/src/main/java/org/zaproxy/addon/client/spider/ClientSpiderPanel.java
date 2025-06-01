/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.client.spider;

import java.awt.BorderLayout;
import java.awt.EventQueue;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JToolBar;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jdesktop.swingx.JXTable;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.client.ClientOptions;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.zap.model.ScanController;
import org.zaproxy.zap.model.ScanListenner2;
import org.zaproxy.zap.view.ScanPanel2;
import org.zaproxy.zap.view.ZapTable;

@SuppressWarnings("serial")
public class ClientSpiderPanel extends ScanPanel2<ClientSpider, ScanController<ClientSpider>>
        implements ScanListenner2 {

    public static final String HTTP_MESSAGE_CONTAINER_NAME = "ClientSpiderHttpMessageContainer";

    private static final long serialVersionUID = 1L;

    private static final Logger LOGGER = LogManager.getLogger(ClientSpiderPanel.class);

    private static final String ZERO_REQUESTS_LABEL_TEXT = "0";

    private static final TaskTableModel EMPTY_ACTIONS_TABLE_MODEL = new TaskTableModel();
    private static final UrlTableModel EMPTY_URL_TABLE_MODEL = new UrlTableModel();
    private static final MessagesTableModel EMPTY_MESSAGES_TABLE_MODEL = new MessagesTableModel();

    public static final String PANEL_NAME = "ClientPanel";

    private static final String ADDED_NODES_CONTAINER_NAME = "ClientAddedNodesContainer";

    private static final String TASKS_CONTAINER_NAME = "ClientTasksContainer";

    private JPanel mainPanel;
    private JTabbedPane tabbedPane;
    private JButton scanButton;
    private ZapTable addedNodesTable;
    private JScrollPane addedNodesTableScrollPane;
    private JLabel addedCountNameLabel;
    private JLabel addedCountValueLabel;
    private JLabel countCrawledUrlsLabel;
    private ZapTable tasksTable;
    private ZapTable messagesTable;
    private JScrollPane tasksTableScrollPane;

    private ExtensionClientIntegration extension;
    private ClientOptions clientOptions;

    public ClientSpiderPanel(
            ExtensionClientIntegration extension,
            SpiderScanController controller,
            ClientOptions clientOptions) {
        super("client.spider", ExtensionClientIntegration.getIcon(), controller);
        this.extension = extension;
        this.clientOptions = clientOptions;
    }

    @Override
    protected JPanel getWorkPanel() {
        if (mainPanel == null) {
            mainPanel = new JPanel(new BorderLayout());

            tabbedPane = new JTabbedPane();
            tabbedPane.addTab(
                    Constant.messages.getString("client.spider.panel.tab.addednodes"),
                    getAddedNodesTableScrollPane());
            tabbedPane.addTab(
                    Constant.messages.getString("client.spider.panel.tab.tasks"),
                    getTasksTableScrollPane());
            messagesTable = new MessagesTable(EMPTY_MESSAGES_TABLE_MODEL);
            tabbedPane.addTab(
                    Constant.messages.getString("client.spider.panel.tab.messages"),
                    new JScrollPane(messagesTable));
            tabbedPane.setSelectedIndex(0);

            mainPanel.add(tabbedPane);
        }
        return mainPanel;
    }

    private JScrollPane getAddedNodesTableScrollPane() {
        if (addedNodesTableScrollPane == null) {
            addedNodesTableScrollPane = new JScrollPane();
            addedNodesTableScrollPane.setName("ClientSpiderAddedUrlsPane");
            addedNodesTableScrollPane.setViewportView(getAddedNodesTable());
        }
        return addedNodesTableScrollPane;
    }

    private JXTable getAddedNodesTable() {
        if (addedNodesTable == null) {
            addedNodesTable = new ZapTable(EMPTY_URL_TABLE_MODEL);
            addedNodesTable.setColumnSelectionAllowed(false);
            addedNodesTable.setCellSelectionEnabled(false);
            addedNodesTable.setRowSelectionAllowed(true);
            addedNodesTable.setAutoCreateRowSorter(true);

            addedNodesTable.setAutoCreateColumnsFromModel(false);

            addedNodesTable.setName(ADDED_NODES_CONTAINER_NAME);
            addedNodesTable.setDoubleBuffered(true);
            addedNodesTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        }
        return addedNodesTable;
    }

    private JLabel getAddedCountNameLabel() {
        if (addedCountNameLabel == null) {
            addedCountNameLabel = new JLabel();
            addedCountNameLabel.setText(
                    Constant.messages.getString("client.spider.toolbar.added.label"));
        }
        return addedCountNameLabel;
    }

    private JLabel getAddedCountValueLabel() {
        if (addedCountValueLabel == null) {
            addedCountValueLabel = new JLabel();
            addedCountValueLabel.setText(ZERO_REQUESTS_LABEL_TEXT);
        }
        return addedCountValueLabel;
    }

    private JScrollPane getTasksTableScrollPane() {
        if (tasksTableScrollPane == null) {
            tasksTableScrollPane = new JScrollPane();
            tasksTableScrollPane.setName("ClientSpiderTasksPane");
            tasksTableScrollPane.setViewportView(getTasksTable());
        }
        return tasksTableScrollPane;
    }

    private JXTable getTasksTable() {
        if (tasksTable == null) {
            tasksTable = new ZapTable(EMPTY_ACTIONS_TABLE_MODEL);
            tasksTable.setColumnSelectionAllowed(false);
            tasksTable.setCellSelectionEnabled(false);
            tasksTable.setRowSelectionAllowed(true);
            tasksTable.setAutoCreateRowSorter(true);

            tasksTable.setAutoCreateColumnsFromModel(false);
            tasksTable.getColumnModel().getColumn(0).setMinWidth(40);
            tasksTable.getColumnModel().getColumn(0).setPreferredWidth(50); // ID

            tasksTable.getColumnModel().getColumn(1).setMinWidth(50);
            tasksTable.getColumnModel().getColumn(1).setPreferredWidth(60); // Action

            tasksTable.getColumnModel().getColumn(2).setMinWidth(300); // URI
            tasksTable.getColumnModel().getColumn(3).setMinWidth(300); // Details
            tasksTable.getColumnModel().getColumn(4).setMinWidth(300); // Error

            tasksTable.getColumnModel().getColumn(5).setMinWidth(60);
            tasksTable.getColumnModel().getColumn(5).setPreferredWidth(70); // Status

            tasksTable.setName(TASKS_CONTAINER_NAME);
            tasksTable.setDoubleBuffered(true);
        }
        return tasksTable;
    }

    @Override
    protected int addToolBarElements(JToolBar toolBar, Location location, int gridX) {
        if (ScanPanel2.Location.afterProgressBar == location) {
            toolBar.add(new JToolBar.Separator(), getGBC(gridX++, 0));
            toolBar.add(
                    new JLabel(Constant.messages.getString("client.spider.toolbar.urls.label")),
                    getGBC(gridX++, 0));
            countCrawledUrlsLabel = new JLabel(ZERO_REQUESTS_LABEL_TEXT);
            toolBar.add(countCrawledUrlsLabel, getGBC(gridX++, 0));
            toolBar.add(new JToolBar.Separator(), getGBC(gridX++, 0));
            toolBar.add(getAddedCountNameLabel(), getGBC(gridX++, 0));
            toolBar.add(getAddedCountValueLabel(), getGBC(gridX++, 0));

            toolBar.add(new JToolBar.Separator(), getGBC(gridX++, 0));
        }
        return gridX;
    }

    /** Update the count of added nodes. */
    public void updateAddedCount() {
        ClientSpider sc = this.getSelectedScanner();
        if (sc != null) {
            this.getAddedCountValueLabel()
                    .setText(Integer.toString(sc.getAddedNodesTableModel().getRowCount()));
            countCrawledUrlsLabel.setText(Integer.toString(sc.getCountCrawledUrls()));
        } else {
            this.getAddedCountValueLabel().setText(ZERO_REQUESTS_LABEL_TEXT);
            countCrawledUrlsLabel.setText(ZERO_REQUESTS_LABEL_TEXT);
        }
    }

    @Override
    public void switchView(final ClientSpider scanner) {
        if (View.isInitialised() && !EventQueue.isDispatchThread()) {
            SwingUtilities.invokeLater(() -> switchView(scanner));
            return;
        }
        if (scanner != null) {
            getAddedNodesTable().setModel(scanner.getAddedNodesTableModel());
            getTasksTable().setModel(scanner.getActionsTableModel());
            messagesTable.setModel(scanner.getMessagesTableModel());
        } else {
            getAddedNodesTable().setModel(EMPTY_URL_TABLE_MODEL);
            getTasksTable().setModel(EMPTY_ACTIONS_TABLE_MODEL);
            messagesTable.setModel(EMPTY_MESSAGES_TABLE_MODEL);
        }
        this.updateAddedCount();
    }

    @Override
    public JButton getNewScanButton() {
        if (scanButton == null) {
            scanButton =
                    new JButton(Constant.messages.getString("client.spider.toolbar.button.new"));
            scanButton.setIcon(ExtensionClientIntegration.getIcon());
            scanButton.addActionListener(e -> extension.showScanDialog(getSiteTreeTarget()));
        }
        return scanButton;
    }

    @Override
    protected int getNumberOfScansToShow() {
        return clientOptions.getMaxScansInUi();
    }

    private SiteNode getSiteTreeTarget() {
        if (!extension.getView().getSiteTreePanel().getTreeSite().isSelectionEmpty()) {
            return (SiteNode)
                    extension
                            .getView()
                            .getSiteTreePanel()
                            .getTreeSite()
                            .getSelectionPath()
                            .getLastPathComponent();
        }
        return null;
    }

    // Overridden to expose the method to the extension
    @Override
    public void unload() {
        super.unload();
    }
}
