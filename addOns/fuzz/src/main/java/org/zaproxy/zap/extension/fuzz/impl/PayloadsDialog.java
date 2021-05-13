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
import java.util.List;
import javax.swing.GroupLayout;
import javax.swing.JPanel;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.fuzz.impl.MessageLocationPayloadsPanel.PayloadsChangedListener;
import org.zaproxy.zap.model.MessageLocation;
import org.zaproxy.zap.view.AbstractFormDialog;

public class PayloadsDialog extends AbstractFormDialog {

    private static final long serialVersionUID = 4152587374142222707L;

    private static final String CONFIRM_BUTTON_LABEL =
            Constant.messages.getString("fuzz.fuzzer.dialog.payloads.button.confirm");

    private List<PayloadTableEntry> payloads;

    private MessageLocationPayloadsPanel payloadsPanel;

    public PayloadsDialog(
            Dialog parent,
            MessageLocation messageLocation,
            List<PayloadTableEntry> payloads,
            PayloadGeneratorsContainer payloadGeneratorsUIHandlers) {
        super(parent, Constant.messages.getString("fuzz.fuzzer.dialog.payloads.title"), false);

        setConfirmButtonEnabled(!payloads.isEmpty());

        this.payloads = payloads;

        payloadsPanel =
                new MessageLocationPayloadsPanel(
                        this, messageLocation, payloads, payloadGeneratorsUIHandlers);
        payloadsPanel.setPayloadsChangedListener(
                new PayloadsChangedListener() {

                    @Override
                    public void payloadAdded(int numberOfPayloads) {
                        setConfirmButtonEnabled(true);
                    }

                    @Override
                    public void payloadRemoved(int numberOfPayloads) {
                        if (numberOfPayloads == 0) {
                            setConfirmButtonEnabled(false);
                        }
                    }
                });

        initView();
        pack();
    }

    @Override
    protected JPanel getFieldsPanel() {
        JPanel fieldsPanel = new JPanel();

        GroupLayout layout = new GroupLayout(fieldsPanel);
        fieldsPanel.setLayout(layout);
        layout.setAutoCreateGaps(true);

        layout.setHorizontalGroup(layout.createSequentialGroup().addComponent(payloadsPanel));
        layout.setVerticalGroup(layout.createSequentialGroup().addComponent(payloadsPanel));

        return fieldsPanel;
    }

    @Override
    public void dispose() {
        super.dispose();

        payloadsPanel.clear();
    }

    @Override
    protected String getConfirmButtonLabel() {
        return CONFIRM_BUTTON_LABEL;
    }

    @Override
    protected void performAction() {
        payloads = payloadsPanel.getPayloads();
    }

    public List<PayloadTableEntry> getPayloads() {
        return payloads;
    }
}
