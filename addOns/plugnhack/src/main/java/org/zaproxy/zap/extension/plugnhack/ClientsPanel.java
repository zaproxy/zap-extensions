/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.plugnhack;

import java.awt.CardLayout;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Rectangle;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import javax.swing.DefaultListModel;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextPane;
import javax.swing.JToolBar;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import org.apache.log4j.Logger;
import org.jdesktop.swingx.JXTable;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.httppanel.HttpPanelRequest;
import org.zaproxy.zap.extension.httppanel.HttpPanelResponse;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.view.LayoutHelper;
import org.zaproxy.zap.view.ZapTable;
import org.zaproxy.zap.view.ZapToggleButton;

public class ClientsPanel extends AbstractPanel implements MonitoredPageListener {

    public static final String CLIENTS_PANEL_NAME = "pnhClientsAlert";
    public static final String CLIENTS_LIST_NAME = "pnhClientsList";
    public static final String CLIENTS_MESSAGE_TABLE_NAME = "pnhMessageTable";

    private static final long serialVersionUID = 1L;
    private static final Logger logger = Logger.getLogger(ClientsPanel.class);

    private ExtensionPlugNHack extension;
    private JPanel panelCommand = null;
    private JSplitPane splitPane = null;
    private JScrollPane clientsScrollPane = null;
    private JScrollPane msgScrollPane = null;

    private DefaultListModel<MonitoredPage> clientsListModel = null;
    private JList<MonitoredPage> clientsList = null;

    private MessageListTableModel msgTableModel = null;
    private JXTable msgTable = null;

    private HttpPanelRequest requestPanel = null;
    private HttpPanelResponse responsePanel = null;

    private boolean showInactiveClients = false;

    /** */
    public ClientsPanel(ExtensionPlugNHack extension) {
        super();
        this.extension = extension;
        this.extension.addMonitoredPageListenner(this);

        this.setLayout(new CardLayout());
        this.setSize(274, 251);
        this.setName(Constant.messages.getString("plugnhack.client.panel.title"));
        this.setIcon(ExtensionPlugNHack.CLIENT_ACTIVE_ICON);
        this.setDefaultAccelerator(
                this.extension
                        .getView()
                        .getMenuShortcutKeyStroke(KeyEvent.VK_C, KeyEvent.SHIFT_DOWN_MASK, false));
        this.setMnemonic(Constant.messages.getChar("plugnhack.client.panel.mnemonic"));

        this.add(getClientsPanel(), getClientsPanel().getName());
    }

    public void setDisplayPanel(HttpPanelRequest requestPanel, HttpPanelResponse responsePanel) {
        this.requestPanel = requestPanel;
        this.responsePanel = responsePanel;
    }

    private javax.swing.JPanel getClientsPanel() {
        if (panelCommand == null) {

            panelCommand = new javax.swing.JPanel();
            panelCommand.setLayout(new java.awt.GridBagLayout());
            panelCommand.setName(CLIENTS_PANEL_NAME);

            GridBagConstraints gridBagConstraints1 = new GridBagConstraints();
            GridBagConstraints gridBagConstraints2 = new GridBagConstraints();

            gridBagConstraints1.gridx = 0;
            gridBagConstraints1.gridy = 0;
            gridBagConstraints1.weightx = 1.0D;
            gridBagConstraints1.insets = new java.awt.Insets(2, 2, 2, 2);
            gridBagConstraints1.fill = java.awt.GridBagConstraints.HORIZONTAL;
            gridBagConstraints1.anchor = java.awt.GridBagConstraints.NORTHWEST;

            gridBagConstraints2.gridx = 0;
            gridBagConstraints2.gridy = 1;
            gridBagConstraints2.weightx = 1.0;
            gridBagConstraints2.weighty = 1.0;
            gridBagConstraints2.insets = new java.awt.Insets(0, 0, 0, 0);
            gridBagConstraints2.fill = java.awt.GridBagConstraints.BOTH;
            gridBagConstraints2.anchor = java.awt.GridBagConstraints.NORTHWEST;

            // TODO Work in progress
            // panelCommand.add(clientToolbar, gridBagConstraints1);
            panelCommand.add(getSplitPane(), gridBagConstraints2);
        }
        return panelCommand;
    }

    private JSplitPane getSplitPane() {
        if (splitPane == null) {
            splitPane = new JSplitPane();
            splitPane.setName("ClientsPanels");
            splitPane.setDividerSize(3);
            splitPane.setDividerLocation(400);
            splitPane.setOrientation(JSplitPane.HORIZONTAL_SPLIT);
            JPanel panel = new JPanel();
            panel.setLayout(new GridBagLayout());

            // Add the toolbar
            JToolBar clientToolbar = new JToolBar();
            clientToolbar.setFloatable(false);
            clientToolbar.setEnabled(true);
            clientToolbar.setRollover(true);
            clientToolbar.setFont(FontUtils.getFont("Dialog"));

            JButton customBreak = new JButton();
            customBreak.setIcon(
                    DisplayUtils.getScaledIcon(
                            new ImageIcon(
                                    ZAP.class.getResource("/resource/icon/16/break_add.png"))));
            customBreak.setToolTipText(
                    Constant.messages.getString("plugnhack.client.button.custom.tooltip"));
            customBreak.addActionListener(
                    new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            extension.getBrkManager().handleAddBreakpoint(new ClientMessage());
                        }
                    });
            clientToolbar.add(customBreak);

            final ZapToggleButton activeSwitch = new ZapToggleButton();
            activeSwitch.setSelected(true);
            activeSwitch.setIcon(
                    DisplayUtils.getScaledIcon(ExtensionPlugNHack.CLIENT_INACTIVE_ICON));
            activeSwitch.setSelectedIcon(
                    DisplayUtils.getScaledIcon(ExtensionPlugNHack.CLIENT_ACTIVE_ICON));
            activeSwitch.setToolTipText(
                    Constant.messages.getString("plugnhack.client.button.active.off"));
            activeSwitch.setSelectedToolTipText(
                    Constant.messages.getString("plugnhack.client.button.active.on"));
            activeSwitch.addActionListener(
                    new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            showInactiveClients = !activeSwitch.isSelected();
                            refreshClientList();
                        }
                    });
            clientToolbar.add(activeSwitch);

            panel.add(clientToolbar, LayoutHelper.getGBC(0, 0, 1, 0.0D));

            panel.add(getClientScrollPane(), LayoutHelper.getGBC(0, 1, 1, 1.0D, 1.0D));

            splitPane.setLeftComponent(panel);

            splitPane.setRightComponent(getMsgScrollPane());
            splitPane.setPreferredSize(new Dimension(100, 200));
        }
        return splitPane;
    }

    private JScrollPane getClientScrollPane() {
        if (clientsScrollPane == null) {
            clientsScrollPane = new JScrollPane();
            clientsScrollPane.setName("pnhClientsScrollPane");
            clientsScrollPane.setViewportView(getClientsList());
        }
        return clientsScrollPane;
    }

    private JScrollPane getMsgScrollPane() {
        if (msgScrollPane == null) {
            msgScrollPane = new JScrollPane();
            msgScrollPane.setName("pnhMsgScrollPane");
            // Display instructions until the first message is received
            msgScrollPane.setViewportView(getInitialMessage());
        }
        return msgScrollPane;
    }

    private JTextPane getInitialMessage() {
        JTextPane initialMessage = new JTextPane();
        initialMessage.setEditable(false);
        initialMessage.setFont(FontUtils.getFont("Dialog"));
        initialMessage.setContentType("text/html");
        initialMessage.setText(Constant.messages.getString("plugnhack.label.initialMessage"));
        return initialMessage;
    }

    private DefaultListModel<MonitoredPage> getClientsListModel() {
        if (this.clientsListModel == null) {
            this.clientsListModel = new DefaultListModel<MonitoredPage>();
        }
        return this.clientsListModel;
    }

    private JList<MonitoredPage> getClientsList() {
        if (this.clientsList == null) {
            this.clientsList = new JList<MonitoredPage>(this.getClientsListModel());
            this.clientsList.setName(CLIENTS_LIST_NAME);
            this.clientsList.setCellRenderer(new ClientListCellRenderer());

            clientsList.addMouseListener(
                    new java.awt.event.MouseAdapter() {
                        @Override
                        public void mousePressed(java.awt.event.MouseEvent e) {
                            // TODO should use e.isPopupTrigger() now?
                            if (SwingUtilities.isRightMouseButton(e)) {
                                // Select list item on right click
                                int Idx = clientsList.locationToIndex(e.getPoint());
                                if (Idx >= 0) {
                                    Rectangle Rect = clientsList.getCellBounds(Idx, Idx);
                                    Idx = Rect.contains(e.getPoint().x, e.getPoint().y) ? Idx : -1;
                                }
                                if (Idx < 0
                                        || !clientsList.getSelectionModel().isSelectedIndex(Idx)) {
                                    clientsList.getSelectionModel().clearSelection();
                                    if (Idx >= 0) {
                                        clientsList
                                                .getSelectionModel()
                                                .setSelectionInterval(Idx, Idx);
                                    }
                                }
                                View.getSingleton()
                                        .getPopupMenu()
                                        .show(e.getComponent(), e.getX(), e.getY());
                            }
                        }
                    });
        }
        return this.clientsList;
    }

    private MessageListTableModel getMessageModel() {
        if (this.msgTableModel == null) {
            this.msgTableModel = new MessageListTableModel();
        }
        return this.msgTableModel;
    }

    private JXTable getMessageTable() {
        if (this.msgTable == null) {
            this.msgTable = new ZapTable(this.getMessageModel());
            this.msgTable.setName(CLIENTS_MESSAGE_TABLE_NAME);
            this.setMessageTableColumnSizes();
            this.msgTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

            this.msgTable.addMouseListener(
                    new MouseAdapter() {
                        @Override
                        public void mousePressed(MouseEvent e) {
                            // Enable the right click menu items
                            if (SwingUtilities.isRightMouseButton(e)) {

                                // Select table item
                                int row = msgTable.rowAtPoint(e.getPoint());
                                if (row < 0 || !msgTable.getSelectionModel().isSelectedIndex(row)) {
                                    msgTable.getSelectionModel().clearSelection();
                                    if (row >= 0) {
                                        msgTable.getSelectionModel().setSelectionInterval(row, row);
                                    }
                                }

                                View.getSingleton()
                                        .getPopupMenu()
                                        .show(e.getComponent(), e.getX(), e.getY());
                            }
                        }
                    });

            this.msgTable
                    .getSelectionModel()
                    .addListSelectionListener(
                            new ListSelectionListener() {
                                @Override
                                public void valueChanged(ListSelectionEvent e) {
                                    ClientMessage msg = getSelectedClientMessage();
                                    if (msg != null) {
                                        // Show the selected message in the Request tab
                                        displayMessage(msg);
                                        // Get the focus back so that the arrow keys work
                                        msgTable.requestFocus();
                                    }
                                }
                            });
        }
        return this.msgTable;
    }

    private void setMessageTableColumnSizes() {

        msgTable.getColumnModel().getColumn(0).setMinWidth(50);
        msgTable.getColumnModel().getColumn(0).setPreferredWidth(100); // Received

        msgTable.getColumnModel().getColumn(1).setMinWidth(20);
        msgTable.getColumnModel().getColumn(1).setPreferredWidth(20); // Changed icon

        msgTable.getColumnModel().getColumn(2).setMinWidth(50);
        msgTable.getColumnModel().getColumn(2).setPreferredWidth(100); // Client

        msgTable.getColumnModel().getColumn(3).setMinWidth(100);
        msgTable.getColumnModel().getColumn(3).setPreferredWidth(200); // Type

        msgTable.getColumnModel().getColumn(4).setMinWidth(100);
        msgTable.getColumnModel().getColumn(4).setPreferredWidth(400); // Data
    }

    private void displayMessage(ClientMessage msg) {
        if (msg != null) {
            requestPanel.clearView(true);
            responsePanel.clearView(false);
            requestPanel.setMessage(msg);
            requestPanel.setTabFocus();
        }
    }

    public void reset() {
        refreshClientList();
        getMessageModel().removeAllElements();
    }

    private void refreshClientList() {
        DefaultListModel<MonitoredPage> model = this.getClientsListModel();
        model.removeAllElements();
        for (MonitoredPage page : this.extension.getActiveClients()) {
            model.addElement(page);
        }
        if (this.showInactiveClients) {
            for (MonitoredPage page : this.extension.getInactiveClients()) {
                model.addElement(page);
            }
        }
    }

    @Override
    public void startMonitoringPageEvent(MonitoredPage page) {
        if (this.showInactiveClients) {
            // Add before inactive pages
            for (int i = 0; i < this.getClientsListModel().size(); i++) {
                if (!this.getClientsListModel().elementAt(i).isActive()) {
                    this.getClientsListModel().add(i, page);
                    return;
                }
            }
        }
        this.getClientsListModel().addElement(page);
    }

    @Override
    public void stopMonitoringPageEvent(MonitoredPage page) {
        this.getClientsListModel().removeElement(page);
        if (this.showInactiveClients) {
            // Add back at the end, which will also cause the icon to change
            this.getClientsListModel().addElement(page);
        }
    }

    @Override
    public ApiResponse messageReceived(final ClientMessage message) {
        SwingUtilities.invokeLater(
                new Runnable() {
                    @Override
                    public void run() {
                        try {
                            if (getMessageModel().getRowCount() == 0) {
                                // First message, switch from the instructions
                                msgScrollPane.setViewportView(getMessageTable());
                            }
                            getMessageModel().addClientMessage(message);

                        } catch (Exception e) {
                            logger.error(e.getMessage(), e);
                        }
                    }
                });
        return null;
    }

    protected ClientMessage getSelectedClientMessage() {
        int row = this.getMessageTable().getSelectedRow();
        if (row >= 0) {
            return this.getMessageModel().getClientMessageAtRow(row);
        }
        return null;
    }

    public void messageChanged(final ClientMessage msg) {
        SwingUtilities.invokeLater(
                new Runnable() {
                    @Override
                    public void run() {
                        getMessageModel().clientMessageChanged(msg);
                    }
                });
    }
}
