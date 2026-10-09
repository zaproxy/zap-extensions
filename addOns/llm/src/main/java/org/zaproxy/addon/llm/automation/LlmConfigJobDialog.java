/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.llm.automation;

import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;
import javax.swing.JButton;
import javax.swing.JOptionPane;
import javax.swing.JTable;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.llm.automation.LlmConfigJob.Provider;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class LlmConfigJobDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String[] TAB_LABELS = {
        "llm.configjob.dialog.tab.params", "llm.configjob.dialog.tab.providers"
    };

    private static final String TITLE = "llm.configjob.dialog.title";
    private static final String NAME_PARAM = "llm.configjob.dialog.name";
    private static final String DELETE_EXISTING_PARAM = "llm.configjob.dialog.deleteexisting";
    private static final String DEFAULT_PROVIDER_PARAM = "llm.configjob.dialog.defaultprovider";
    private static final String DEFAULT_MODEL_PARAM = "llm.configjob.dialog.defaultmodel";

    private final LlmConfigJob job;
    private final LlmProviderTableModel providersModel = new LlmProviderTableModel();
    private final JTable providersTable = new JTable(providersModel);
    private final JButton modifyButton =
            new JButton(Constant.messages.getString("automation.dialog.button.modify"));
    private final JButton removeButton =
            new JButton(Constant.messages.getString("automation.dialog.button.remove"));

    public LlmConfigJobDialog(LlmConfigJob job) {
        super(
                View.getSingleton().getMainFrame(),
                TITLE,
                DisplayUtils.getScaledDimension(600, 350),
                TAB_LABELS);
        this.job = job;
        providersModel.setProviders(job.getData().getProviders());

        LlmConfigJob.Parameters p = job.getParameters();
        addTextField(0, NAME_PARAM, job.getData().getName());
        addCheckBoxField(0, DELETE_EXISTING_PARAM, Boolean.TRUE.equals(p.getDeleteExisting()));
        addTextField(0, DEFAULT_PROVIDER_PARAM, p.getDefaultProvider());
        addTextField(0, DEFAULT_MODEL_PARAM, p.getDefaultModel());
        addPadding(0);

        JButton addButton =
                new JButton(Constant.messages.getString("automation.dialog.button.add"));
        addButton.addActionListener(e -> showProviderDialog(null, -1));
        modifyButton.setEnabled(false);
        modifyButton.addActionListener(e -> modifySelectedProvider());
        removeButton.setEnabled(false);
        removeButton.addActionListener(e -> removeSelectedProvider());

        providersTable
                .getSelectionModel()
                .addListSelectionListener(
                        e -> {
                            boolean enabled = providersTable.getSelectedRowCount() == 1;
                            modifyButton.setEnabled(enabled);
                            removeButton.setEnabled(enabled);
                        });
        providersTable.addMouseListener(
                new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent me) {
                        if (me.getClickCount() == 2 && providersTable.getSelectedRow() >= 0) {
                            modifySelectedProvider();
                        }
                    }
                });
        addTableField(1, providersTable, List.of(addButton, modifyButton, removeButton));
    }

    private void showProviderDialog(Provider provider, int index) {
        new AddProviderDialog(
                        providersModel,
                        provider,
                        index,
                        p -> job.validateProvider(p, getBoolValue(DELETE_EXISTING_PARAM)))
                .setVisible(true);
    }

    private void modifySelectedProvider() {
        int row = providersTable.getSelectedRow();
        showProviderDialog(providersModel.getProviders().get(row), row);
    }

    private void removeSelectedProvider() {
        if (JOptionPane.OK_OPTION
                == View.getSingleton()
                        .showConfirmDialog(
                                this,
                                Constant.messages.getString(
                                        "llm.configjob.dialog.remove.confirm"))) {
            providersModel.remove(providersTable.getSelectedRow());
        }
    }

    @Override
    public void save() {
        job.getData().setName(getStringValue(NAME_PARAM));
        job.getParameters().setDeleteExisting(getBoolValue(DELETE_EXISTING_PARAM));
        job.getParameters().setDefaultProvider(getStringValue(DEFAULT_PROVIDER_PARAM));
        job.getParameters().setDefaultModel(getStringValue(DEFAULT_MODEL_PARAM));
        job.getData().setProviders(providersModel.getProviders());
        job.resetAndSetChanged();
    }

    @Override
    public String validateFields() {
        return null;
    }
}
