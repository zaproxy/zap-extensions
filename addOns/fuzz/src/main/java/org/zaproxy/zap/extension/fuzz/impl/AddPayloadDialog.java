/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.fuzz.impl;

import java.awt.CardLayout;
import java.awt.Window;
import java.awt.event.ItemEvent;
import javax.swing.GroupLayout;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUI;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUIPanel;
import org.zaproxy.zap.model.MessageLocation;
import org.zaproxy.zap.utils.SortedComboBoxModel;
import org.zaproxy.zap.view.AbstractFormDialog;

public class AddPayloadDialog extends AbstractFormDialog {

    private static final long serialVersionUID = 4460797449668634319L;

    private static final String DIALOG_TITLE =
            Constant.messages.getString("fuzz.fuzzer.dialog.add.payload.title");

    private static final String CONFIRM_BUTTON_LABEL =
            Constant.messages.getString("fuzz.fuzzer.dialog.add.payload.button.confirm");

    private static final String TYPE_FIELD_LABEL =
            Constant.messages.getString("fuzz.fuzzer.dialog.add.payload.label.type");

    private JComboBox<String> payloadUIHandlersComboBox;

    private PayloadGeneratorUI<?, ?> selectedPayloadGeneratorUI;

    private CardLayout contentsPanelCardLayout;
    private JPanel contentsPanel;

    private PayloadGeneratorsContainer payloadGeneratorsUIHandlers;

    private PayloadGeneratorUIPanel<?, ?, ?> currentPanel;

    public AddPayloadDialog(
            Window owner,
            PayloadGeneratorsContainer payloadGeneratorsUIHandlers,
            MessageLocation messageLocation) {
        super(owner, DIALOG_TITLE, false);

        this.payloadGeneratorsUIHandlers = payloadGeneratorsUIHandlers;

        getPayloadUIHandlersComboBox().setSelectedIndex(-1);
        for (PayloadGeneratorUIPanel<?, ?, ?> panel : payloadGeneratorsUIHandlers.getPanels()) {
            panel.init(messageLocation);
        }

        contentsPanelCardLayout = new CardLayout();
        contentsPanel = new JPanel(contentsPanelCardLayout);

        for (String payloadType : payloadGeneratorsUIHandlers.getPayloadUIHandlersNames()) {
            contentsPanel.add(
                    payloadGeneratorsUIHandlers.getPanel(payloadType).getComponent(), payloadType);
        }

        getPayloadUIHandlersComboBox()
                .setSelectedItem(payloadGeneratorsUIHandlers.getDefaultPanelName());

        initView();

        setConfirmButtonEnabled(true);
    }

    @Override
    protected JPanel getFieldsPanel() {
        JPanel fieldsPanel = new JPanel();

        GroupLayout groupLayout = new GroupLayout(fieldsPanel);
        fieldsPanel.setLayout(groupLayout);
        groupLayout.setAutoCreateGaps(true);
        groupLayout.setAutoCreateContainerGaps(true);

        JLabel typeLabel = new JLabel(TYPE_FIELD_LABEL);

        groupLayout.setHorizontalGroup(
                groupLayout
                        .createParallelGroup()
                        .addGroup(
                                groupLayout
                                        .createSequentialGroup()
                                        .addGroup(
                                                groupLayout
                                                        .createParallelGroup(
                                                                GroupLayout.Alignment.TRAILING)
                                                        .addComponent(typeLabel))
                                        .addGroup(
                                                groupLayout
                                                        .createParallelGroup(
                                                                GroupLayout.Alignment.LEADING)
                                                        .addComponent(
                                                                getPayloadUIHandlersComboBox())))
                        .addComponent(contentsPanel));

        groupLayout.setVerticalGroup(
                groupLayout
                        .createSequentialGroup()
                        .addGroup(
                                groupLayout
                                        .createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(typeLabel)
                                        .addComponent(getPayloadUIHandlersComboBox()))
                        .addComponent(contentsPanel));

        return fieldsPanel;
    }

    @Override
    protected String getConfirmButtonLabel() {
        return CONFIRM_BUTTON_LABEL;
    }

    @Override
    protected void clearFields() {
        for (PayloadGeneratorUIPanel<?, ?, ?> panel : payloadGeneratorsUIHandlers.getPanels()) {
            panel.clear();
        }
        contentsPanel.removeAll();
    }

    @Override
    protected boolean validateFields() {
        return currentPanel.validate();
    }

    @Override
    protected void performAction() {
        selectedPayloadGeneratorUI = currentPanel.getPayloadGeneratorUI();
    }

    public PayloadGeneratorUI<?, ?> getPayloadGeneratorUI() {
        return selectedPayloadGeneratorUI;
    }

    protected JComboBox<String> getPayloadUIHandlersComboBox() {
        if (payloadUIHandlersComboBox == null) {
            payloadUIHandlersComboBox = new JComboBox<>(new SortedComboBoxModel<String>());
            for (String name : payloadGeneratorsUIHandlers.getPayloadUIHandlersNames()) {
                payloadUIHandlersComboBox.addItem(name);
            }

            payloadUIHandlersComboBox.addItemListener(
                    e -> {
                        if (ItemEvent.SELECTED == e.getStateChange()) {
                            String panelName = (String) e.getItem();

                            currentPanel = payloadGeneratorsUIHandlers.getPanel(panelName);
                            contentsPanelCardLayout.show(contentsPanel, panelName);

                            setHelpTarget(currentPanel.getHelpTarget());
                        }
                    });
        }
        return payloadUIHandlersComboBox;
    }
}
