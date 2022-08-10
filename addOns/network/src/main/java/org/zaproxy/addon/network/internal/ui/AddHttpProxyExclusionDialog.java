/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.network.internal.ui;

import java.awt.Dialog;
import javax.swing.GroupLayout;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.network.internal.client.HttpProxyExclusion;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.AbstractFormDialog;

@SuppressWarnings("serial")
public class AddHttpProxyExclusionDialog extends AbstractFormDialog {

    private static final long serialVersionUID = 1L;

    protected final JPanel fieldsPanel;
    protected final ZapTextField hostTextField;
    protected final JCheckBox enabledCheckBox;

    protected HttpProxyExclusion httpProxyExclusion;

    public AddHttpProxyExclusionDialog(Dialog owner) {
        this(
                owner,
                Constant.messages.getString(
                        "network.ui.options.connection.httpproxy.exclusions.add.title"));
    }

    protected AddHttpProxyExclusionDialog(Dialog owner, String title) {
        super(owner, title, false);

        fieldsPanel = new JPanel();

        GroupLayout layout = new GroupLayout(fieldsPanel);
        fieldsPanel.setLayout(layout);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        JLabel hostLabel =
                new JLabel(
                        Constant.messages.getString(
                                "network.ui.options.connection.httpproxy.exclusions.add.field.host"));
        hostTextField = new ZapTextField(25);
        hostTextField.getDocument().addDocumentListener(new EnableButtonDocumentListener());
        hostLabel.setLabelFor(hostTextField);

        JLabel enabledLabel =
                new JLabel(
                        Constant.messages.getString(
                                "network.ui.options.connection.httpproxy.exclusions.add.field.enabled"));
        enabledCheckBox = new JCheckBox();
        enabledLabel.setLabelFor(enabledCheckBox);

        layout.setHorizontalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                        .addComponent(hostLabel)
                                        .addComponent(enabledLabel))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                        .addComponent(hostTextField)
                                        .addComponent(enabledCheckBox)));

        layout.setVerticalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(hostLabel)
                                        .addComponent(hostTextField))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(enabledLabel)
                                        .addComponent(enabledCheckBox)));

        initView();
    }

    @Override
    protected JPanel getFieldsPanel() {
        return fieldsPanel;
    }

    @Override
    protected String getConfirmButtonLabel() {
        return Constant.messages.getString(
                "network.ui.options.connection.httpproxy.exclusions.add.button");
    }

    @Override
    protected void init() {
        hostTextField.setText("");
        hostTextField.discardAllEdits();
        enabledCheckBox.setSelected(true);
        httpProxyExclusion = null;
    }

    @Override
    protected boolean validateFields() {
        String value = hostTextField.getText();

        try {
            HttpProxyExclusion.createHostPattern(value);
        } catch (IllegalArgumentException e) {
            JOptionPane.showMessageDialog(
                    this,
                    Constant.messages.getString(
                            "network.ui.options.connection.httpproxy.exclusions.warn.invalidregex.message",
                            e.getMessage()),
                    Constant.messages.getString(
                            "network.ui.options.connection.httpproxy.exclusions.warn.invalidregex.title"),
                    JOptionPane.INFORMATION_MESSAGE);
            hostTextField.requestFocusInWindow();
            return false;
        }

        return true;
    }

    @Override
    protected void performAction() {
        String value = hostTextField.getText();
        httpProxyExclusion =
                new HttpProxyExclusion(
                        HttpProxyExclusion.createHostPattern(value), enabledCheckBox.isSelected());
    }

    public HttpProxyExclusion getHttpProxyExclusion() {
        HttpProxyExclusion httpProxyExclusion = this.httpProxyExclusion;
        this.httpProxyExclusion = null;
        return httpProxyExclusion;
    }

    private class EnableButtonDocumentListener implements DocumentListener {

        @Override
        public void removeUpdate(DocumentEvent e) {
            checkAndEnableConfirmButton(e);
        }

        @Override
        public void insertUpdate(DocumentEvent e) {
            checkAndEnableConfirmButton(e);
        }

        @Override
        public void changedUpdate(DocumentEvent e) {
            checkAndEnableConfirmButton(e);
        }

        private void checkAndEnableConfirmButton(DocumentEvent e) {
            setConfirmButtonEnabled(e.getDocument().getLength() > 0);
        }
    }
}
