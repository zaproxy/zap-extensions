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

@SuppressWarnings("serial")
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

    private JButton addContextButton = null;
    private JButton modifyContextButton = null;
    private JButton removeContextButton = null;

    private JTable contextsTable = null;
    private ContextsTableModel contextsModel = null;

    private JButton addEnvVarButton = null;
    private JButton modifyEnvVarButton = null;
    private JButton removeEnvVarButton = null;

    private JTable envVarTable = null;
    private EnvVarTableModel envVarModel = null;

    public EnvironmentDialog(AutomationEnvironment env) {
        super(
                View.getSingleton().getMainFrame(),
                TITLE,
                DisplayUtils.getScaledDimension(500, 300),
                TAB_LABELS);
        this.env = env;

        List<JButton> contextButtons = new ArrayList<>();
        contextButtons.add(getAddContextButton());
        contextButtons.add(getModifyContextButton());
        contextButtons.add(getRemoveContextButton());

        this.addTableField(0, getContextsTable(), contextButtons);

        this.addCheckBoxField(
                1, FAIL_ON_ERROR_PARAM, env.getData().getParameters().getFailOnError());
        this.addCheckBoxField(
                1, FAIL_ON_WARNING_PARAM, env.getData().getParameters().getFailOnWarning());
        this.addCheckBoxField(
                1, PROGRESS_TO_STDOUT_PARAM, env.getData().getParameters().getProgressToStdout());
        this.addPadding(1);

        List<JButton> envVarButtons = new ArrayList<>();
        envVarButtons.add(getAddEnvVarButton());
        envVarButtons.add(getModifyEnvVarButton());
        envVarButtons.add(getRemoveEnvVarButton());

        this.addTableField(2, getEnvVarsTable(), envVarButtons);
    }

    @Override
    public void save() {
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
        this.env.getData().setVars(this.getEnvVarsModel().getEnvVarMap());
        this.env.getPlan().setChanged();
    }

    @Override
    public String validateFields() {
        if (this.getContextsModel().getContexts().isEmpty()) {
            return Constant.messages.getString("automation.dialog.env.error.nocontext");
        }
        return null;
    }

    private JButton getAddContextButton() {
        if (this.addContextButton == null) {
            this.addContextButton =
                    new JButton(Constant.messages.getString("automation.dialog.button.add"));
            this.addContextButton.addActionListener(
                    e -> {
                        ContextDialog dialog = new ContextDialog(this);
                        dialog.setVisible(true);
                    });
        }
        return this.addContextButton;
    }

    private JButton getModifyContextButton() {
        if (this.modifyContextButton == null) {
            this.modifyContextButton =
                    new JButton(Constant.messages.getString("automation.dialog.button.modify"));
            modifyContextButton.setEnabled(false);
            this.modifyContextButton.addActionListener(
                    e -> {
                        int row = getContextsTable().getSelectedRow();
                        ContextDialog dialog =
                                new ContextDialog(
                                        this, this.contextsModel.getContexts().get(row).getData());
                        dialog.setVisible(true);
                    });
        }
        return this.modifyContextButton;
    }

    private JButton getRemoveContextButton() {
        if (this.removeContextButton == null) {
            this.removeContextButton =
                    new JButton(Constant.messages.getString("automation.dialog.button.remove"));
            this.removeContextButton.setEnabled(false);
            final EnvironmentDialog parent = this;
            this.removeContextButton.addActionListener(
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
        return this.removeContextButton;
    }

    private JTable getContextsTable() {
        if (contextsTable == null) {
            contextsTable = new JTable();
            contextsTable.setModel(getContextsModel());
            contextsTable
                    .getSelectionModel()
                    .addListSelectionListener(
                            e -> {
                                boolean singleRowSelected =
                                        getContextsTable().getSelectedRowCount() == 1;
                                modifyContextButton.setEnabled(singleRowSelected);
                                removeContextButton.setEnabled(singleRowSelected);
                            });
            contextsTable.addMouseListener(
                    new MouseAdapter() {
                        @Override
                        public void mouseClicked(MouseEvent me) {
                            if (me.getClickCount() == 2) {
                                int row = contextsTable.getSelectedRow();
                                if (row == -1) {
                                    return;
                                }
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

    private JButton getAddEnvVarButton() {
        if (this.addEnvVarButton == null) {
            this.addEnvVarButton =
                    new JButton(Constant.messages.getString("automation.dialog.button.add"));
            this.addEnvVarButton.addActionListener(
                    e -> {
                        EnvVarDialog dialog = new EnvVarDialog(this);
                        dialog.setVisible(true);
                    });
        }
        return this.addEnvVarButton;
    }

    private JButton getModifyEnvVarButton() {
        if (this.modifyEnvVarButton == null) {
            this.modifyEnvVarButton =
                    new JButton(Constant.messages.getString("automation.dialog.button.modify"));
            modifyEnvVarButton.setEnabled(false);
            this.modifyEnvVarButton.addActionListener(
                    e -> {
                        int row = getEnvVarsTable().getSelectedRow();
                        EnvVarDialog dialog =
                                new EnvVarDialog(this, this.envVarModel.getEnvVars().get(row));
                        dialog.setVisible(true);
                    });
        }
        return this.modifyEnvVarButton;
    }

    private JButton getRemoveEnvVarButton() {
        if (this.removeEnvVarButton == null) {
            this.removeEnvVarButton =
                    new JButton(Constant.messages.getString("automation.dialog.button.remove"));
            this.removeEnvVarButton.setEnabled(false);
            final EnvironmentDialog parent = this;
            this.removeEnvVarButton.addActionListener(
                    e -> {
                        if (JOptionPane.OK_OPTION
                                == View.getSingleton()
                                        .showConfirmDialog(
                                                parent,
                                                Constant.messages.getString(
                                                        "automation.dialog.env.remove.confirm"))) {
                            getEnvVarsModel().remove(getEnvVarsTable().getSelectedRow());
                        }
                    });
        }
        return this.removeEnvVarButton;
    }

    private JTable getEnvVarsTable() {
        if (envVarTable == null) {
            envVarTable = new JTable();
            envVarTable.setModel(getEnvVarsModel());
            envVarTable
                    .getSelectionModel()
                    .addListSelectionListener(
                            e -> {
                                boolean singleRowSelected =
                                        getEnvVarsTable().getSelectedRowCount() == 1;
                                modifyEnvVarButton.setEnabled(singleRowSelected);
                                removeEnvVarButton.setEnabled(singleRowSelected);
                            });
            envVarTable.addMouseListener(
                    new MouseAdapter() {
                        @Override
                        public void mouseClicked(MouseEvent me) {
                            if (me.getClickCount() == 2) {
                                int row = envVarTable.getSelectedRow();
                                if (row == -1) {
                                    return;
                                }
                                EnvVarDialog dialog =
                                        new EnvVarDialog(
                                                EnvironmentDialog.this,
                                                envVarModel.getEnvVars().get(row));
                                dialog.setVisible(true);
                            }
                        }
                    });
        }
        return envVarTable;
    }

    private EnvVarTableModel getEnvVarsModel() {
        if (envVarModel == null) {
            envVarModel = new EnvVarTableModel();
            envVarModel.setEnvVars(env.getData().getVars());
        }
        return envVarModel;
    }

    public void addEnvVar(EnvVarTableModel.EnvVar envVar) {
        getEnvVarsModel().add(envVar);
    }
}
