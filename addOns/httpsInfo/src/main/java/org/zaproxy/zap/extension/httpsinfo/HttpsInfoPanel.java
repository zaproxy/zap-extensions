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
package org.zaproxy.zap.extension.httpsinfo;

import java.awt.CardLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.GridBagConstraints;
import java.awt.event.ItemEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseEvent;
import javax.swing.Box;
import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JToolBar;
import javax.swing.SwingUtilities;
import javax.swing.table.TableCellRenderer;

import org.jdesktop.swingx.JXTable;
import org.jdesktop.swingx.renderer.DefaultTableRenderer;
import org.jdesktop.swingx.renderer.MappedValue;
import org.jdesktop.swingx.renderer.StringValues;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.utils.SortedComboBoxModel;
import org.zaproxy.zap.utils.TableExportButton;
import org.zaproxy.zap.view.ZapToggleButton;

public class HttpsInfoPanel extends AbstractPanel {

    private static final long serialVersionUID = 1L;


    public static final String PANEL_NAME = "httpsinfopanel";

    private ExtensionHttpsInfo extension = null;
    private JPanel panelCommand = null;
    private JToolBar panelToolbar = null;
    private JScrollPane jScrollPane = null;

    private String currentSite = null;
    private JComboBox<String> siteSelect = null;
    private SortedComboBoxModel<String> siteModel = new SortedComboBoxModel<>();

    private JXTable httpsinfoTable = null;
    private HttpsInfoTableModel httpsInfoModel = new HttpsInfoTableModel();

    private TableExportButton<JXTable> exportButton = null;
    private ZapToggleButton enableButton = null;


    public HttpsInfoPanel(ExtensionHttpsInfo extension) {
        super();
        this.extension = extension;
        this.setLayout(new CardLayout());
        this.setSize(474, 600);
        this.setName(Constant.messages.getString("httpsinfo.panel.title"));
        this.setIcon(ExtensionHttpsInfo.HTTPSINFO_ICON);
        this.setDefaultAccelerator(
                this.extension
                        .getView()
                        .getMenuShortcutKeyStroke(
                                KeyEvent.VK_T,
                                KeyEvent.ALT_DOWN_MASK | KeyEvent.SHIFT_DOWN_MASK,
                                false));
        this.setMnemonic(Constant.messages.getChar("httpsinfo.panel.mnemonic"));
        this.add(getPanelCommand(), getPanelCommand().getName());
        this.getEnableToggleButton().setSelected(extension.isHttpsInfoEnabled());
    }


    /**
     * This method initializes panelCommand
     *
     * @return javax.swing.JPanel
     */
    private javax.swing.JPanel getPanelCommand() {
        if (panelCommand == null) {

            panelCommand = new javax.swing.JPanel();
            panelCommand.setLayout(new java.awt.GridBagLayout());
            panelCommand.setName("Params");

            GridBagConstraints gridBagConstraints1 = new GridBagConstraints();
            GridBagConstraints gridBagConstraints2 = new GridBagConstraints();

            gridBagConstraints1.gridx = 0;
            gridBagConstraints1.gridy = 0;
            gridBagConstraints1.insets = new java.awt.Insets(2, 2, 2, 2);
            gridBagConstraints1.anchor = java.awt.GridBagConstraints.NORTHWEST;
            gridBagConstraints1.fill = java.awt.GridBagConstraints.HORIZONTAL;
            gridBagConstraints1.weightx = 1.0D;
            gridBagConstraints2.gridx = 0;
            gridBagConstraints2.gridy = 1;
            gridBagConstraints2.weightx = 1.0;
            gridBagConstraints2.weighty = 1.0;
            gridBagConstraints2.fill = java.awt.GridBagConstraints.BOTH;
            gridBagConstraints2.insets = new java.awt.Insets(0, 0, 0, 0);
            gridBagConstraints2.anchor = java.awt.GridBagConstraints.NORTHWEST;

            panelCommand.add(this.getPanelToolbar(), gridBagConstraints1);
            panelCommand.add(getJScrollPane(), gridBagConstraints2);
        }
        return panelCommand;
    }

    private javax.swing.JToolBar getPanelToolbar() {
        if (panelToolbar == null) {

            panelToolbar = new javax.swing.JToolBar();
            panelToolbar.setEnabled(true);
            panelToolbar.setFloatable(false);
            panelToolbar.setRollover(true);
            panelToolbar.setPreferredSize(new java.awt.Dimension(800, 30));
            panelToolbar.setFont(new java.awt.Font("Dialog", java.awt.Font.PLAIN, 12));
            panelToolbar.setName("HttpsInfoToolbar");

            panelToolbar.add(
                    new JLabel(Constant.messages.getString("httpsinfo.toolbar.site.label")));
            panelToolbar.add(getSiteSelect());
            panelToolbar.add(getExportButton());
            panelToolbar.add(getEnableToggleButton());

            panelToolbar.add(Box.createHorizontalGlue());
        }
        return panelToolbar;
    }

    private JScrollPane getJScrollPane() {
        if (jScrollPane == null) {
            jScrollPane = new JScrollPane();
            jScrollPane.setViewportView(getHttpsInfoModel());
            jScrollPane.setFont(new java.awt.Font("Dialog", java.awt.Font.PLAIN, 11));
        }
        return jScrollPane;
    }

    protected JXTable getHttpsInfoModel() {
        if (httpsinfoTable == null) {
            httpsinfoTable =
                    new JXTable(httpsInfoModel) {
                        private static final long serialVersionUID = -1422894398829082869L;

                        @Override
                        public String getToolTipText(MouseEvent e) {
                            String tip = "";
                            int rowIndex = rowAtPoint(e.getPoint());

                            if (rowIndex != -1) {
                                tip =
                                        httpsInfoModel
                                                .getCertificate(convertRowIndexToModel(rowIndex))
                                                .getSubjectDN();
                            }

                            return tip.isEmpty() ? null : tip;
                        }
                    };

            httpsinfoTable.setColumnSelectionAllowed(true);
            httpsinfoTable.setCellSelectionEnabled(false);
            httpsinfoTable.setRowSelectionAllowed(true);
            httpsinfoTable.setAutoCreateRowSorter(true);
            httpsinfoTable.setColumnControlVisible(true);
            TableCellRenderer renderer =
                    new DefaultTableRenderer(
                            new MappedValue(
                                    StringValues.TO_STRING,
                                    item -> null),
                            JLabel.LEADING);
            httpsinfoTable.setDefaultRenderer(Certification.class, renderer);

            httpsinfoTable.setName(PANEL_NAME);
            httpsinfoTable.setFont(new java.awt.Font("Dialog", java.awt.Font.PLAIN, 11));
            httpsinfoTable.setDoubleBuffered(true);
        }
        return httpsinfoTable;
    }

    private JComboBox<String> getSiteSelect() {
        if (siteSelect == null) {
            siteSelect = new JComboBox<>(siteModel);
            siteSelect.addItem(Constant.messages.getString("params.toolbar.site.select"));
            siteSelect.setPreferredSize(new Dimension(250, 80));
            siteSelect.setSelectedIndex(0);

            siteSelect.addActionListener(
                    e -> {
                        String item = (String) siteSelect.getSelectedItem();
                        if (item != null && siteSelect.getSelectedIndex() > 0) {
                            siteSelected(item);
                        }
                    });
        }
        return siteSelect;
    }

    public void addSite(String site) {
        if (siteModel.getIndexOf(site) < 0) {
            siteModel.addElement(site);
            if (siteModel.getSize() == 2 && currentSite == null) {
                // First site added, automatically select it
                this.getSiteSelect().setSelectedIndex(1);
                siteSelected(site);
            }
        }
    }

    void siteSelected(String site) {
        if (!site.equals(currentSite)) {
            siteModel.setSelectedItem(site);
            httpsInfoModel = extension.getHttpsInfoModelForSite(site);
            this.getHttpsInfoModel().setModel(httpsInfoModel);
            currentSite = site;
        }
    }

    public void reset() {
        currentSite = null;

        siteModel.removeAllElements();
        siteSelect.addItem(Constant.messages.getString("httpsinfo.toolbar.site.select"));
        siteSelect.setSelectedIndex(0);

        httpsInfoModel.removeAllElements();
        httpsInfoModel.fireTableDataChanged();

        httpsinfoTable.setModel(httpsInfoModel);
    }

    /**
     * Gets the current selected site.
     *
     * @return the current site
     */
    public String getCurrentSite() {
        return currentSite;
    }

    protected String getSelectedCertificationName() {
        if (this.getHttpsInfoModel().getSelectedRow() >= 0) {
            int modelRow =
                    getHttpsInfoModel()
                            .convertRowIndexToModel(getHttpsInfoModel().getSelectedRow());
            return httpsInfoModel.getCertificate(modelRow).getSubjectDN();
        }
        return null;
    }

    private TableExportButton<JXTable> getExportButton() {
        if (exportButton == null) {
            exportButton = new TableExportButton<>(getHttpsInfoModel());
        }
        return exportButton;
    }

    ZapToggleButton getEnableToggleButton() {
        if (enableButton == null) {
            enableButton =
                    new ZapToggleButton(
                            Constant.messages.getString("httpsinfo.toolbar.toggle.state.enabled"),
                            true);
            enableButton.setIcon(
                    new ImageIcon(
                            HttpsInfoPanel.class.getResource(
                                    ExtensionHttpsInfo.RESOURCE + "/off.png")));
            enableButton.setToolTipText(
                    Constant.messages.getString("httpsinfo.toolbar.toggle.state.disabled.tooltip"));
            enableButton.setSelectedIcon(
                    new ImageIcon(
                            HttpsInfoPanel.class.getResource(
                                    ExtensionHttpsInfo.RESOURCE + "/on.png")));
            enableButton.setSelectedToolTipText(
                    Constant.messages.getString("httpsinfo.toolbar.toggle.state.enabled.tooltip"));
            enableButton.addItemListener(
                    event -> {
                        if (event.getStateChange() == ItemEvent.SELECTED) {
                            enableButton.setText(
                                    Constant.messages.getString(
                                            "httpsinfo.toolbar.toggle.state.enabled"));
                            extension.setHttpsInfo(true);
                        } else {
                            enableButton.setText(
                                    Constant.messages.getString(
                                            "httpsinfo.toolbar.toggle.state.disabled"));
                            extension.setHttpsInfo(false);
                        }
                    });
        }
        return enableButton;
    }
}
