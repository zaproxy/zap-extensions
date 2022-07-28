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
package org.zaproxy.zap.extension.alertFilters.automation;

import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JButton;
import javax.swing.JOptionPane;
import javax.swing.JTable;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class AlertFilterJobDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String[] TAB_LABELS = {
        "alertFilters.automation.dialog.tab.params", "alertFilters.automation.dialog.tab.filters"
    };

    private static final String TITLE = "alertFilters.automation.dialog.title";
    private static final String NAME_PARAM = "automation.dialog.all.name";
    private static final String DELETE_GLOBAL_PARAM = "alertFilters.automation.dialog.deleteglobal";

    private AlertFilterJob job;

    private JButton addButton = null;
    private JButton modifyButton = null;
    private JButton removeButton = null;

    private JTable alertFilterTable = null;
    private AlertFilterTableModel alertFilterModel = null;

    public AlertFilterJobDialog(AlertFilterJob job) {
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
        this.addCheckBoxField(
                0,
                DELETE_GLOBAL_PARAM,
                JobUtils.unBox(this.job.getData().getParameters().getDeleteGlobalAlerts()));
        this.addPadding(0);

        this.addTableField(1, getAlertFilterTable(), buttons);
    }

    @Override
    public void save() {
        this.job.getData().setName(this.getStringValue(NAME_PARAM));
        this.job
                .getData()
                .getParameters()
                .setDeleteGlobalAlerts(this.getBoolValue(DELETE_GLOBAL_PARAM));
        this.job.getData().setAlertFilters(this.getAlertFilterModel().getAlertFilters());
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
                        AddAlertFilterDialog dialog =
                                new AddAlertFilterDialog(job, getAlertFilterModel());
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
                        int row = getAlertFilterTable().getSelectedRow();
                        AddAlertFilterDialog dialog =
                                new AddAlertFilterDialog(
                                        job,
                                        getAlertFilterModel(),
                                        getAlertFilterModel().getAlertFilters().get(row),
                                        row);
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
            final AlertFilterJobDialog parent = this;
            this.removeButton.addActionListener(
                    e -> {
                        if (JOptionPane.OK_OPTION
                                == View.getSingleton()
                                        .showConfirmDialog(
                                                parent,
                                                Constant.messages.getString(
                                                        "automation.dialog.requestor.remove.confirm"))) {
                            getAlertFilterModel().remove(getAlertFilterTable().getSelectedRow());
                        }
                    });
        }
        return this.removeButton;
    }

    private JTable getAlertFilterTable() {
        if (alertFilterTable == null) {
            alertFilterTable = new JTable();
            alertFilterTable.setModel(getAlertFilterModel());
            alertFilterTable
                    .getColumnModel()
                    .getColumn(0)
                    .setPreferredWidth(DisplayUtils.getScaledSize(200));
            alertFilterTable
                    .getColumnModel()
                    .getColumn(1)
                    .setPreferredWidth(DisplayUtils.getScaledSize(80));
            alertFilterTable
                    .getColumnModel()
                    .getColumn(2)
                    .setPreferredWidth(DisplayUtils.getScaledSize(120));
            alertFilterTable
                    .getSelectionModel()
                    .addListSelectionListener(
                            e -> {
                                boolean enabled = getAlertFilterTable().getSelectedRowCount() == 1;
                                modifyButton.setEnabled(enabled);
                                removeButton.setEnabled(enabled);
                            });
            alertFilterTable.addMouseListener(
                    new MouseAdapter() {
                        @Override
                        public void mouseClicked(MouseEvent me) {
                            if (me.getClickCount() == 2) {
                                int row = getAlertFilterTable().getSelectedRow();
                                AddAlertFilterDialog dialog =
                                        new AddAlertFilterDialog(
                                                job,
                                                getAlertFilterModel(),
                                                getAlertFilterModel().getAlertFilters().get(row),
                                                row);
                                dialog.setVisible(true);
                            }
                        }
                    });
        }
        return alertFilterTable;
    }

    private AlertFilterTableModel getAlertFilterModel() {
        if (alertFilterModel == null) {
            alertFilterModel = new AlertFilterTableModel();
            alertFilterModel.setAlertFilters(job.getData().getAlertFilters());
        }
        return alertFilterModel;
    }
}
