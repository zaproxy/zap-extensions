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
import java.awt.Dialog;
import java.awt.event.ItemEvent;
import javax.swing.GroupLayout;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.fuzz.FuzzerMessageProcessor;
import org.zaproxy.zap.extension.fuzz.FuzzerMessageProcessorUI;
import org.zaproxy.zap.extension.fuzz.FuzzerMessageProcessorUIPanel;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.utils.SortedComboBoxModel;
import org.zaproxy.zap.view.AbstractFormDialog;

public class AddFuzzerMessageProcessorDialog<
                T1 extends Message, T2 extends FuzzerMessageProcessor<T1>>
        extends AbstractFormDialog {

    private static final long serialVersionUID = 4460797449668634319L;

    private static final String DIALOG_TITLE =
            Constant.messages.getString("fuzz.fuzzer.dialog.add.messageprocessor.title");

    private static final String CONFIRM_BUTTON_LABEL =
            Constant.messages.getString("fuzz.fuzzer.dialog.add.messageprocessor.button.confirm");

    private static final String TYPE_FIELD_LABEL =
            Constant.messages.getString("fuzz.fuzzer.dialog.add.messageprocessor.label.type");

    private JComboBox<String> payloadUIHandlersComboBox;

    private FuzzerMessageProcessorUI<T1, T2> selectedFuzzerMessageProcessorUI;

    private CardLayout contentsPanelCardLayout;
    private JPanel contentsPanel;

    private FuzzerMessageProcessors<T1, T2> fuzzerMessageProcessors;

    private FuzzerMessageProcessorUIPanel<T1, T2, ?> currentPanel;

    public AddFuzzerMessageProcessorDialog(
            Dialog owner, FuzzerMessageProcessors<T1, T2> fuzzerMessageProcessors, T1 message) {
        super(owner, DIALOG_TITLE, false);

        this.fuzzerMessageProcessors = fuzzerMessageProcessors;

        getMessageProcessorUIHandlersComboBox().setSelectedIndex(-1);
        for (FuzzerMessageProcessorUIPanel<T1, T2, ?> panel : fuzzerMessageProcessors.getPanels()) {
            panel.init(message);
        }
        contentsPanelCardLayout = new CardLayout();
        contentsPanel = new JPanel(contentsPanelCardLayout);

        for (String payloadType :
                fuzzerMessageProcessors.getFuzzerMessageProcessorUIHandlersNames()) {
            contentsPanel.add(
                    fuzzerMessageProcessors.getPanel(payloadType).getComponent(), payloadType);
        }

        getMessageProcessorUIHandlersComboBox()
                .setSelectedItem(fuzzerMessageProcessors.getDefaultPanelName());

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
                                                                getMessageProcessorUIHandlersComboBox())))
                        .addComponent(contentsPanel));

        groupLayout.setVerticalGroup(
                groupLayout
                        .createSequentialGroup()
                        .addGroup(
                                groupLayout
                                        .createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(typeLabel)
                                        .addComponent(getMessageProcessorUIHandlersComboBox()))
                        .addComponent(contentsPanel));

        return fieldsPanel;
    }

    @Override
    protected String getConfirmButtonLabel() {
        return CONFIRM_BUTTON_LABEL;
    }

    @Override
    protected void clearFields() {
        for (FuzzerMessageProcessorUIPanel<T1, T2, ?> panel : fuzzerMessageProcessors.getPanels()) {
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
        selectedFuzzerMessageProcessorUI = currentPanel.getFuzzerMessageProcessorUI();
    }

    public FuzzerMessageProcessorUI<T1, T2> getFuzzerMessageProcessorUI() {
        return selectedFuzzerMessageProcessorUI;
    }

    protected JComboBox<String> getMessageProcessorUIHandlersComboBox() {
        if (payloadUIHandlersComboBox == null) {
            payloadUIHandlersComboBox = new JComboBox<>(new SortedComboBoxModel<String>());
            for (String name : fuzzerMessageProcessors.getFuzzerMessageProcessorUIHandlersNames()) {
                payloadUIHandlersComboBox.addItem(name);
            }

            payloadUIHandlersComboBox.addItemListener(
                    e -> {
                        if (ItemEvent.SELECTED == e.getStateChange()) {
                            String panelName = (String) e.getItem();

                            currentPanel = fuzzerMessageProcessors.getPanel(panelName);
                            contentsPanelCardLayout.show(contentsPanel, panelName);

                            setHelpTarget(currentPanel.getHelpTarget());
                        }
                    });
        }
        return payloadUIHandlersComboBox;
    }
}
