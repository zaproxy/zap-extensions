/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.addon.encoder;

import java.awt.Frame;
import javax.swing.GroupLayout;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.apache.commons.lang.StringUtils;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.encoder.processors.EncodeDecodeProcessorItem;
import org.zaproxy.addon.encoder.processors.EncodeDecodeProcessors;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.AbstractFormDialog;

@SuppressWarnings("serial")
class AddEncodeDecodeOutputPanelDialog extends AbstractFormDialog {

    private static final long serialVersionUID = 1L;

    private static final String DIALOG_TITLE =
            Constant.messages.getString("encoder.dialog.addoutputpanel.title");
    private static final String NAME_FIELD_LABEL =
            Constant.messages.getString("encoder.dialog.addoutputpanel.field.name.label");
    private static final String SCRIPTS_FIELD_LABEL =
            Constant.messages.getString("encoder.dialog.addoutputpanel.field.scripts.label");
    private static final String CONFIRM_BUTTON_LABEL =
            Constant.messages.getString("encoder.dialog.addoutputpanel.button.confirm");

    private final EncodeDecodeProcessors encodeDecodeProcessors;

    private ZapTextField nameTextField;
    private String outputPanelName;
    private JComboBox<String> processorComboboxField;
    private String processorId;

    public AddEncodeDecodeOutputPanelDialog(Frame owner, EncodeDecodeProcessors processors) {
        super(owner, DIALOG_TITLE);
        encodeDecodeProcessors = processors;
    }

    @Override
    protected JPanel getFieldsPanel() {
        JPanel fieldsPanel = new JPanel();

        GroupLayout layout = new GroupLayout(fieldsPanel);
        fieldsPanel.setLayout(layout);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        JLabel nameLabel = new JLabel(NAME_FIELD_LABEL);
        JLabel scriptsLabel = new JLabel(SCRIPTS_FIELD_LABEL);

        layout.setHorizontalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                        .addComponent(nameLabel)
                                        .addComponent(scriptsLabel))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                        .addComponent(getNameTextField())
                                        .addComponent(getProcessorComboboxField())));

        layout.setVerticalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(nameLabel)
                                        .addComponent(getNameTextField()))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(scriptsLabel)
                                        .addComponent(getProcessorComboboxField())));

        return fieldsPanel;
    }

    @Override
    protected String getConfirmButtonLabel() {
        return CONFIRM_BUTTON_LABEL;
    }

    @Override
    protected void init() {
        getNameTextField().setText("");
        refreshScriptItems();
    }

    private ZapTextField getNameTextField() {
        if (nameTextField == null) {
            nameTextField = new ZapTextField(25);
        }

        return nameTextField;
    }

    private void checkAndEnableConfirmButton() {
        setConfirmButtonEnabled(processorComboboxField.getSelectedIndex() >= 0);
    }

    private JComboBox<String> getProcessorComboboxField() {
        if (processorComboboxField == null) {
            processorComboboxField = new JComboBox<>();
            processorComboboxField.addItemListener(e -> checkAndEnableConfirmButton());
        }
        return processorComboboxField;
    }

    private void refreshScriptItems() {
        processorComboboxField.removeAllItems();
        for (EncodeDecodeProcessorItem item : encodeDecodeProcessors.getProcessorItems()) {
            processorComboboxField.addItem(item.getName());
        }
    }

    @Override
    public void setVisible(boolean b) {
        if (b) {
            outputPanelName = null;
            processorId = null;
        }
        super.setVisible(b);
    }

    @Override
    protected boolean validateFields() {
        return true;
    }

    @Override
    protected void performAction() {
        outputPanelName = getNameTextField().getText();
        String selectedProcessorName = getProcessorComboboxField().getSelectedItem().toString();
        String selectedProcessorId = findProcessorIdByName(selectedProcessorName);
        processorId = selectedProcessorId;
    }

    private String findProcessorIdByName(String selectedProcessorName) {
        for (EncodeDecodeProcessorItem item : encodeDecodeProcessors.getProcessorItems()) {
            if (StringUtils.equals(item.getName(), selectedProcessorName)) {
                return item.getId();
            }
        }
        return null;
    }

    @Override
    protected void clearFields() {
        getNameTextField().setText("");
        getNameTextField().discardAllEdits();
    }

    public String getOutputPanelName() {
        return outputPanelName;
    }

    public String getProcessorId() {
        return processorId;
    }
}
