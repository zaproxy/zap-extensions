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

import java.awt.Dialog;
import javax.swing.GroupLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.fuzz.payloads.Payload;
import org.zaproxy.zap.extension.fuzz.payloads.processor.PayloadProcessor;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.PayloadProcessorUI;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.PayloadProcessorUIPanel;
import org.zaproxy.zap.utils.ResettableAutoCloseableIterator;
import org.zaproxy.zap.view.AbstractFormDialog;

public class ModifyProcessorDialog<
                T0 extends Payload,
                T1 extends PayloadProcessor<T0>,
                T2 extends PayloadProcessorUI<T0, T1>>
        extends AbstractFormDialog {

    private static final long serialVersionUID = 8111848758566016134L;

    private static final String DIALOG_TITLE =
            Constant.messages.getString("fuzz.fuzzer.dialog.modify.processor.title");
    private static final String TYPE_LABEL =
            Constant.messages.getString("fuzz.fuzzer.dialog.modify.processor.label.type");
    private static final String CONFIRM_BUTTON_LABEL =
            Constant.messages.getString("fuzz.fuzzer.dialog.modify.processor.button.confirm");

    private final String nameType;
    private T2 payloadProcessorUI;

    private PayloadProcessorUIPanel<T0, T1, T2> contentPanel;

    private PayloadPreviewPanel previewPanel;

    public ModifyProcessorDialog(
            Dialog owner,
            PayloadProcessorUIPanel<T0, T1, T2> panel,
            T2 processorUI,
            ResettableAutoCloseableIterator<Payload> payloads) {
        super(owner, DIALOG_TITLE, false);

        nameType = processorUI.getName();

        previewPanel = new PayloadPreviewPanel(payloads);
        previewPanel.setPayloadProcessorUIPanel(panel);

        contentPanel = panel;
        contentPanel.setPayloadProcessorUI(processorUI);
        contentPanel.getComponent().setVisible(true);

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
                        .addComponent(contentPanel.getComponent())
                        .addComponent(previewPanel.getPanel()));

        groupLayout.setVerticalGroup(
                groupLayout
                        .createSequentialGroup()
                        .addGroup(
                                groupLayout
                                        .createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(typeLabel)
                                        .addComponent(nameTypeLabel))
                        .addComponent(contentPanel.getComponent())
                        .addComponent(previewPanel.getPanel()));

        return fieldsPanel;
    }

    @Override
    protected String getConfirmButtonLabel() {
        return CONFIRM_BUTTON_LABEL;
    }

    @Override
    protected void clearFields() {
        contentPanel.clear();
        previewPanel.clear();
    }

    @Override
    protected boolean validateFields() {
        return contentPanel.validate();
    }

    @Override
    protected void performAction() {
        payloadProcessorUI = contentPanel.getPayloadProcessorUI();
    }

    public T2 getPayloadProcessorUI() {
        return payloadProcessorUI;
    }
}
