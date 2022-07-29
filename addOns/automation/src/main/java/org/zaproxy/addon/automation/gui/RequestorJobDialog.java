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
package org.zaproxy.addon.automation.gui;

import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JButton;
import javax.swing.JOptionPane;
import javax.swing.JTable;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.automation.jobs.RequestorJob;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class RequestorJobDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String[] TAB_LABELS = {
        "automation.dialog.tab.params", "automation.dialog.requestor.tab.requests"
    };

    private static final String TITLE = "automation.dialog.requestor.title";
    private static final String NAME_PARAM = "automation.dialog.all.name";
    private static final String USER_PARAM = "automation.dialog.all.user";

    private RequestorJob job;

    private JButton addButton = null;
    private JButton modifyButton = null;
    private JButton removeButton = null;

    private JTable rulesTable = null;
    private RequestsTableModel rulesModel = null;

    public RequestorJobDialog(RequestorJob job) {
        super(
                View.getSingleton().getMainFrame(),
                TITLE,
                DisplayUtils.getScaledDimension(500, 300),
                TAB_LABELS);
        this.job = job;

        List<JButton> buttons = new ArrayList<>();
        buttons.add(getAddButton());
        buttons.add(getModifyButton());
        buttons.add(getRemoveButton());

        this.addTextField(0, NAME_PARAM, this.job.getData().getName());

        List<String> users = job.getEnv().getAllUserNames();
        // Add blank option
        users.add(0, "");
        this.addComboField(0, USER_PARAM, users, this.job.getData().getParameters().getUser());

        this.addPadding(0);

        this.addTableField(1, getRulesTable(), buttons);
    }

    @Override
    public void save() {
        this.job.getData().setName(this.getStringValue(NAME_PARAM));
        this.job.getData().getParameters().setUser(this.getStringValue(USER_PARAM));
        job.getData().setRequests(this.getRulesModel().getRules());
        this.job.resetAndSetChanged();
    }

    @Override
    public String validateFields() {
        // Nothing to do
        return null;
    }

    private JButton getAddButton() {
        if (this.addButton == null) {
            this.addButton =
                    new JButton(Constant.messages.getString("automation.dialog.button.add"));
            this.addButton.addActionListener(
                    e -> {
                        AddRequestDialog dialog = new AddRequestDialog(getRulesModel());
                        dialog.setVisible(true);
                    });
        }
        return this.addButton;
    }

    private JButton getModifyButton() {
        if (this.modifyButton == null) {
            this.modifyButton =
                    new JButton(Constant.messages.getString("automation.dialog.button.modify"));
            this.modifyButton.setEnabled(false);
            this.modifyButton.addActionListener(
                    e -> {
                        int row = getRulesTable().getSelectedRow();
                        AddRequestDialog dialog =
                                new AddRequestDialog(
                                        getRulesModel(), getRulesModel().getRules().get(row), row);
                        dialog.setVisible(true);
                    });
        }
        return this.modifyButton;
    }

    private JButton getRemoveButton() {
        if (this.removeButton == null) {
            this.removeButton =
                    new JButton(Constant.messages.getString("automation.dialog.button.remove"));
            this.removeButton.setEnabled(false);
            final RequestorJobDialog parent = this;
            this.removeButton.addActionListener(
                    e -> {
                        if (JOptionPane.OK_OPTION
                                == View.getSingleton()
                                        .showConfirmDialog(
                                                parent,
                                                Constant.messages.getString(
                                                        "automation.dialog.requestor.remove.confirm"))) {
                            getRulesModel().remove(getRulesTable().getSelectedRow());
                        }
                    });
        }
        return this.removeButton;
    }

    private JTable getRulesTable() {
        if (rulesTable == null) {
            rulesTable = new JTable();
            rulesTable.setModel(getRulesModel());
            rulesTable
                    .getColumnModel()
                    .getColumn(0)
                    .setPreferredWidth(DisplayUtils.getScaledSize(80));
            rulesTable
                    .getColumnModel()
                    .getColumn(1)
                    .setPreferredWidth(DisplayUtils.getScaledSize(240));
            rulesTable
                    .getColumnModel()
                    .getColumn(2)
                    .setPreferredWidth(DisplayUtils.getScaledSize(80));
            rulesTable
                    .getSelectionModel()
                    .addListSelectionListener(
                            e -> {
                                boolean singleRowSelected =
                                        getRulesTable().getSelectedRowCount() == 1;
                                modifyButton.setEnabled(singleRowSelected);
                                removeButton.setEnabled(singleRowSelected);
                            });
            rulesTable.addMouseListener(
                    new MouseAdapter() {
                        @Override
                        public void mouseClicked(MouseEvent me) {
                            if (me.getClickCount() == 2) {
                                int row = getRulesTable().getSelectedRow();
                                if (row == -1) {
                                    return;
                                }
                                AddRequestDialog dialog =
                                        new AddRequestDialog(
                                                getRulesModel(),
                                                getRulesModel().getRules().get(row),
                                                row);
                                dialog.setVisible(true);
                            }
                        }
                    });
        }
        return rulesTable;
    }

    private RequestsTableModel getRulesModel() {
        if (rulesModel == null) {
            rulesModel = new RequestsTableModel();
            rulesModel.setRules(job.getData().getRequests());
        }
        return rulesModel;
    }
}
