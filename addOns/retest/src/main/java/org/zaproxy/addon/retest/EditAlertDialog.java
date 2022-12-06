/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.retest;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.HeadlessException;
import java.awt.event.WindowAdapter;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractDialog;

@SuppressWarnings("serial")
public class EditAlertDialog extends AbstractDialog {

    private static final long serialVersionUID = 1L;

    private JPanel editAlertPanel = null;
    private EditAlertPanel alertEditPanel = null;
    private JButton btnOk = null;
    private JButton btnCancel = null;
    private AlertData alertData;
    private PlanTableModel tableModel = null;
    private int rowIdx;

    public EditAlertDialog(PlanTableModel tableModel, int rowIdx) throws HeadlessException {
        this.tableModel = tableModel;
        this.rowIdx = rowIdx;
        this.alertData = tableModel.getRow(rowIdx);

        this.setTitle(Constant.messages.getString("retest.edit.dialog.title"));
        this.setContentPane(getJPanel());
        this.getAlertEditPanel().displayAlert(alertData);
        this.addWindowListener(
                new WindowAdapter() {
                    @Override
                    public void windowClosing(java.awt.event.WindowEvent e) {
                        btnCancel.doClick();
                    }
                });
        pack();
    }

    private JPanel getJPanel() {
        if (editAlertPanel == null) {
            GridBagConstraints gridBagConstraints15 = new GridBagConstraints();
            GridBagConstraints gridBagConstraints13 = new GridBagConstraints();
            JLabel jLabel2 = new JLabel();
            GridBagConstraints gridBagConstraints3 = new GridBagConstraints();
            GridBagConstraints gridBagConstraints2 = new GridBagConstraints();

            editAlertPanel = new JPanel();
            editAlertPanel.setLayout(new GridBagLayout());
            gridBagConstraints2.gridx = 1;
            gridBagConstraints2.gridy = 5;
            gridBagConstraints2.insets = new java.awt.Insets(2, 2, 2, 2);
            gridBagConstraints2.anchor = java.awt.GridBagConstraints.EAST;
            gridBagConstraints3.gridx = 2;
            gridBagConstraints3.gridy = 5;
            gridBagConstraints3.insets = new java.awt.Insets(2, 2, 2, 10);
            gridBagConstraints3.anchor = java.awt.GridBagConstraints.EAST;

            gridBagConstraints13.gridx = 0;
            gridBagConstraints13.gridy = 5;
            gridBagConstraints13.fill = java.awt.GridBagConstraints.HORIZONTAL;
            gridBagConstraints13.weightx = 1.0D;
            gridBagConstraints13.insets = new java.awt.Insets(2, 10, 2, 5);

            gridBagConstraints15.weightx = 1.0D;
            gridBagConstraints15.weighty = 1.0D;
            gridBagConstraints15.fill = java.awt.GridBagConstraints.BOTH;
            gridBagConstraints15.insets = new java.awt.Insets(2, 2, 2, 2);
            gridBagConstraints15.gridwidth = 3;
            gridBagConstraints15.gridx = 0;
            gridBagConstraints15.gridy = 2;
            gridBagConstraints15.anchor = java.awt.GridBagConstraints.NORTHWEST;
            gridBagConstraints15.ipadx = 0;
            gridBagConstraints15.ipady = 10;

            editAlertPanel.add(getAlertEditPanel(), gridBagConstraints15);
            editAlertPanel.add(jLabel2, gridBagConstraints13);
            editAlertPanel.add(getBtnCancel(), gridBagConstraints2);
            editAlertPanel.add(getBtnOk(), gridBagConstraints3);
        }
        return editAlertPanel;
    }

    private JButton getBtnOk() {
        if (btnOk == null) {
            btnOk = new JButton();
            btnOk.setText(Constant.messages.getString("retest.edit.dialog.save"));
            btnOk.addActionListener(
                    e -> {
                        AlertData updatedAlert = alertEditPanel.getAlertData();
                        tableModel.updateRow(rowIdx, updatedAlert);
                        dispose();
                    });
        }
        return btnOk;
    }

    private JButton getBtnCancel() {
        if (btnCancel == null) {
            btnCancel = new JButton();
            btnCancel.setText(Constant.messages.getString("retest.edit.dialog.cancel"));
            btnCancel.setEnabled(true);
            btnCancel.addActionListener(e -> dispose());
        }
        return btnCancel;
    }

    private EditAlertPanel getAlertEditPanel() {
        if (alertEditPanel == null) {
            alertEditPanel = new EditAlertPanel();
        }
        return alertEditPanel;
    }
}
