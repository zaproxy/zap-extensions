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

import java.util.ArrayList;
import java.util.List;
import javax.swing.JButton;
import javax.swing.JOptionPane;
import javax.swing.JTable;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.automation.jobs.AddOnJob;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

public class AddOnJobDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String TITLE = "automation.dialog.addon.title";
    private static final String NAME_PARAM = "automation.dialog.all.name";
    private static final String UPDATE_ADDONS_PARAM = "automation.dialog.addon.updateaddons";
    private static final String INSTALL_ADDONS_PARAM = "automation.dialog.addon.installaddons";
    private static final String UNINSTALL_ADDONS_PARAM = "automation.dialog.addon.uninstalladdons";

    private AddOnJob job;

    private JButton addInstButton = null;
    private JButton removeInstButton = null;
    private JButton addUninstButton = null;
    private JButton removeUninstButton = null;

    private JTable addOnsInstallTable = null;
    private AddOnsTableModel addOnsInstallModel = null;
    private JTable addOnsUninstallTable = null;
    private AddOnsTableModel addOnsUninstallModel = null;

    public AddOnJobDialog(AddOnJob job) {
        super(View.getSingleton().getMainFrame(), TITLE, DisplayUtils.getScaledDimension(400, 400));
        this.job = job;

        this.addTextField(NAME_PARAM, this.job.getData().getName());

        // XXX Disabled until this can work without breaking things
        // this.addCheckBoxField(UPDATE_ADDONS_PARAM, this.job.getParameters().getUpdateAddOns());

        List<JButton> instButtons = new ArrayList<>();
        instButtons.add(getAddInstButton());
        instButtons.add(getRemoveInstButton());

        this.addTableField(INSTALL_ADDONS_PARAM, getAddOnsInstallTable(), instButtons);

        List<JButton> uninstButtons = new ArrayList<>();
        uninstButtons.add(getAddUninstButton());
        uninstButtons.add(getRemoveUninstButton());

        this.addTableField(UNINSTALL_ADDONS_PARAM, getAddOnsUninstallTable(), uninstButtons);
    }

    private JButton getAddInstButton() {
        if (this.addInstButton == null) {
            this.addInstButton =
                    new JButton(Constant.messages.getString("automation.dialog.button.add"));
            this.addInstButton.addActionListener(
                    e -> {
                        AddAddOnsDialog dialog = new AddAddOnsDialog(getAddOnsInstallModel());
                        dialog.setVisible(true);
                    });
        }
        return this.addInstButton;
    }

    private JButton getRemoveInstButton() {
        if (this.removeInstButton == null) {
            this.removeInstButton =
                    new JButton(Constant.messages.getString("automation.dialog.button.remove"));
            this.removeInstButton.setEnabled(false);
            final AddOnJobDialog parent = this;
            this.removeInstButton.addActionListener(
                    e -> {
                        if (JOptionPane.OK_OPTION
                                == View.getSingleton()
                                        .showConfirmDialog(
                                                parent,
                                                Constant.messages.getString(
                                                        "automation.dialog.addon.remove.confirm"))) {
                            getAddOnsInstallModel()
                                    .remove(getAddOnsInstallTable().getSelectedRow());
                        }
                    });
        }
        return this.removeInstButton;
    }

    private JButton getAddUninstButton() {
        if (this.addUninstButton == null) {
            this.addUninstButton =
                    new JButton(Constant.messages.getString("automation.dialog.button.add"));
            this.addUninstButton.addActionListener(
                    e -> {
                        AddAddOnsDialog dialog = new AddAddOnsDialog(getAddOnsUninstallModel());
                        dialog.setVisible(true);
                    });
        }
        return this.addUninstButton;
    }

    private JButton getRemoveUninstButton() {
        if (this.removeUninstButton == null) {
            this.removeUninstButton =
                    new JButton(Constant.messages.getString("automation.dialog.button.remove"));
            this.removeUninstButton.setEnabled(false);
            final AddOnJobDialog parent = this;
            this.removeUninstButton.addActionListener(
                    e -> {
                        if (JOptionPane.OK_OPTION
                                == View.getSingleton()
                                        .showConfirmDialog(
                                                parent,
                                                Constant.messages.getString(
                                                        "automation.dialog.addon.remove.confirm"))) {
                            getAddOnsUninstallModel()
                                    .remove(getAddOnsUninstallTable().getSelectedRow());
                        }
                    });
        }
        return this.removeUninstButton;
    }

    private JTable getAddOnsInstallTable() {
        if (addOnsInstallTable == null) {
            addOnsInstallTable = new JTable();
            addOnsInstallTable.setModel(getAddOnsInstallModel());
            addOnsInstallTable
                    .getSelectionModel()
                    .addListSelectionListener(
                            e ->
                                    removeInstButton.setEnabled(
                                            getAddOnsInstallTable().getSelectedRowCount() == 1));
        }
        return addOnsInstallTable;
    }

    private AddOnsTableModel getAddOnsInstallModel() {
        if (addOnsInstallModel == null) {
            addOnsInstallModel = new AddOnsTableModel();
            addOnsInstallModel.setAddOns(new ArrayList<>(job.getData().getInstall()));
        }
        return addOnsInstallModel;
    }

    private JTable getAddOnsUninstallTable() {
        if (addOnsUninstallTable == null) {
            addOnsUninstallTable = new JTable();
            addOnsUninstallTable.setModel(getAddOnsUninstallModel());
            addOnsUninstallTable
                    .getSelectionModel()
                    .addListSelectionListener(
                            e ->
                                    removeUninstButton.setEnabled(
                                            getAddOnsUninstallTable().getSelectedRowCount() == 1));
        }
        return addOnsUninstallTable;
    }

    private AddOnsTableModel getAddOnsUninstallModel() {
        if (addOnsUninstallModel == null) {
            addOnsUninstallModel = new AddOnsTableModel();
            addOnsUninstallModel.setAddOns(new ArrayList<>(job.getData().getUninstall()));
        }
        return addOnsUninstallModel;
    }

    @Override
    public void save() {
        this.job.getData().setName(this.getStringValue(NAME_PARAM));
        // XXX Disabled until this can work without breaking things
        // this.job.getParameters().setUpdateAddOns(this.getBoolValue(UPDATE_ADDONS_PARAM));
        List<String> addOns = this.getAddOnsInstallModel().getAddOns();
        if (addOns.isEmpty()) {
            this.job.getData().setInstall(null);
        } else {
            this.job.getData().setInstall(addOns);
        }
        addOns = this.getAddOnsUninstallModel().getAddOns();
        if (addOns.isEmpty()) {
            this.job.getData().setUninstall(null);
        } else {
            this.job.getData().setUninstall(addOns);
        }
        this.job.resetAndSetChanged();
    }

    @Override
    public String validateFields() {
        // Nothing to do
        return null;
    }
}
