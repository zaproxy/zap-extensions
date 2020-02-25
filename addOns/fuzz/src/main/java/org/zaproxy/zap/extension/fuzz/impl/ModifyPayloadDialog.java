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

import java.awt.Window;
import javax.swing.GroupLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.fuzz.payloads.Payload;
import org.zaproxy.zap.extension.fuzz.payloads.generator.PayloadGenerator;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUI;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUIPanel;
import org.zaproxy.zap.view.AbstractFormDialog;

public class ModifyPayloadDialog<
                T extends Payload,
                T2 extends PayloadGenerator<T>,
                T3 extends PayloadGeneratorUI<T, T2>>
        extends AbstractFormDialog {

    private static final long serialVersionUID = 8111848758566016134L;

    private static final String DIALOG_TITLE =
            Constant.messages.getString("fuzz.fuzzer.dialog.modify.payload.title");
    private static final String TYPE_LABEL =
            Constant.messages.getString("fuzz.fuzzer.dialog.modify.payload.label.type");
    private static final String CONFIRM_BUTTON_LABEL =
            Constant.messages.getString("fuzz.fuzzer.dialog.modify.payload.button.confirm");

    private final String nameType;
    private T3 payloadGeneratorUI;

    private PayloadGeneratorUIPanel<T, T2, T3> contentPanel;

    public ModifyPayloadDialog(
            Window owner, PayloadGeneratorUIPanel<T, T2, T3> panel, T3 payloadGeneratorUI) {
        super(owner, DIALOG_TITLE, false);

        nameType = payloadGeneratorUI.getName();

        contentPanel = panel;
        contentPanel.setPayloadGeneratorUI(payloadGeneratorUI);

        setHelpTarget(contentPanel.getHelpTarget());

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

        JLabel typeLabel = new JLabel(TYPE_LABEL);
        JLabel nameTypeLabel = new JLabel(nameType);

        contentPanel.getComponent().setVisible(true);

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
                                                        .addComponent(nameTypeLabel)))
                        .addComponent(contentPanel.getComponent()));

        groupLayout.setVerticalGroup(
                groupLayout
                        .createSequentialGroup()
                        .addGroup(
                                groupLayout
                                        .createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(typeLabel)
                                        .addComponent(nameTypeLabel))
                        .addComponent(contentPanel.getComponent()));

        return fieldsPanel;
    }

    @Override
    protected String getConfirmButtonLabel() {
        return CONFIRM_BUTTON_LABEL;
    }

    @Override
    protected void clearFields() {
        contentPanel.clear();
    }

    @Override
    protected boolean validateFields() {
        return contentPanel.validate();
    }

    @Override
    protected void performAction() {
        payloadGeneratorUI = contentPanel.getPayloadGeneratorUI();
    }

    public T3 getPayloadGeneratorUI() {
        return payloadGeneratorUI;
    }
}
