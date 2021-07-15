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
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.ContextWrapper;
import org.zaproxy.addon.automation.ContextWrapper.Data;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

public class EnvironmentDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String[] TAB_LABELS = {
        "automation.dialog.env.tab.contexts",
        "automation.dialog.tab.params",
        "automation.dialog.env.tab.vars"
    };

    private static final String TITLE = "automation.dialog.env.title";
    private static final String FAIL_ON_ERROR_PARAM = "automation.dialog.env.failonerror";
    private static final String FAIL_ON_WARNING_PARAM = "automation.dialog.env.failonwarning";
    private static final String PROGRESS_TO_STDOUT_PARAM = "automation.dialog.env.progresstostdout";

    private AutomationEnvironment env;

    private JButton addButton = null;
    private JButton modifyButton = null;
    private JButton removeButton = null;

    private JTable contextsTable = null;
    private ContextsTableModel contextsModel = null;

    public EnvironmentDialog(AutomationEnvironment env) {
        super(
                View.getSingleton().getMainFrame(),
                TITLE,
                DisplayUtils.getScaledDimension(500, 300),
                TAB_LABELS);
        this.env = env;

        List<JButton> buttons = new ArrayList<>();
        buttons.add(getAddButton());
        buttons.add(getModifyButton());
        buttons.add(getRemoveButton());

        this.addTableField(0, getContextsTable(), buttons);

        this.addCheckBoxField(
                1, FAIL_ON_ERROR_PARAM, env.getData().getParameters().isFailOnError());
        this.addCheckBoxField(
                1, FAIL_ON_WARNING_PARAM, env.getData().getParameters().isFailOnWarning());
        this.addCheckBoxField(
                1, PROGRESS_TO_STDOUT_PARAM, env.getData().getParameters().isProgressToStdout());
        this.addPadding(1);
    }

    @Override
    public void save() {
        // TODO Auto-generated method stub
        this.env.getData().getParameters().setFailOnError(this.getBoolValue(FAIL_ON_ERROR_PARAM));
        this.env
                .getData()
                .getParameters()
                .setFailOnWarning(this.getBoolValue(FAIL_ON_WARNING_PARAM));
        this.env
                .getData()
                .getParameters()
                .setProgressToStdout(this.getBoolValue(PROGRESS_TO_STDOUT_PARAM));

        this.env.setContexts(this.getContextsModel().getContexts());
    }

    @Override
    public String validateFields() {
        if (this.getContextsModel().getContexts().isEmpty()) {
            return Constant.messages.getString("automation.dialog.env.error.nocontext");
        }
        return null;
    }

    private JButton getAddButton() {
        if (this.addButton == null) {
            this.addButton =
                    new JButton(Constant.messages.getString("automation.dialog.button.add"));
            this.addButton.addActionListener(
                    e -> {
                        ContextDialog dialog = new ContextDialog(this);
                        dialog.setVisible(true);
                    });
        }
        return this.addButton;
    }

    private JButton getModifyButton() {
        if (this.modifyButton == null) {
            this.modifyButton =
                    new JButton(Constant.messages.getString("automation.dialog.button.modify"));
            this.modifyButton.addActionListener(
                    e -> {
                        int row = getContextsTable().getSelectedRow();
                        ContextDialog dialog =
                                new ContextDialog(
                                        this, this.contextsModel.getContexts().get(row).getData());
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
            final EnvironmentDialog parent = this;
            this.removeButton.addActionListener(
                    e -> {
                        if (JOptionPane.OK_OPTION
                                == View.getSingleton()
                                        .showConfirmDialog(
                                                parent,
                                                Constant.messages.getString(
                                                        "automation.dialog.env.remove.confirm"))) {
                            getContextsModel().remove(getContextsTable().getSelectedRow());
                        }
                    });
        }
        return this.removeButton;
    }

    private JTable getContextsTable() {
        if (contextsTable == null) {
            contextsTable = new JTable();
            contextsTable.setModel(getContextsModel());
            contextsTable
                    .getSelectionModel()
                    .addListSelectionListener(
                            e -> {
                                if (getContextsTable().getSelectedRowCount() == 0) {
                                    modifyButton.setEnabled(false);
                                    removeButton.setEnabled(false);
                                } else if (getContextsTable().getSelectedRowCount() == 1) {
                                    modifyButton.setEnabled(true);
                                    removeButton.setEnabled(true);
                                } else {
                                    modifyButton.setEnabled(false);
                                    removeButton.setEnabled(false);
                                }
                            });
            contextsTable.addMouseListener(
                    new MouseAdapter() {
                        @Override
                        public void mouseClicked(MouseEvent me) {
                            if (me.getClickCount() == 2) {
                                int row = contextsTable.getSelectedRow();
                                ContextDialog dialog =
                                        new ContextDialog(
                                                EnvironmentDialog.this,
                                                contextsModel.getContexts().get(row).getData());
                                dialog.setVisible(true);
                            }
                        }
                    });
        }
        return contextsTable;
    }

    private ContextsTableModel getContextsModel() {
        if (contextsModel == null) {
            contextsModel = new ContextsTableModel();
            contextsModel.setContexts(env.getContextWrappers());
        }
        return contextsModel;
    }

    public void addContext(Data context) {
        getContextsModel().add(new ContextWrapper(context));
    }
}
