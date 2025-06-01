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

import javax.swing.GroupLayout;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.view.AbstractFormDialog;

public class PromptHttpProxyPasswordDialog extends AbstractFormDialog {

    private static final long serialVersionUID = 1L;

    private final JPanel fieldsPanel;
    private final JPasswordField passwordField;
    private char[] password;

    public PromptHttpProxyPasswordDialog() {
        super(
                (JFrame) null,
                Constant.messages.getString("network.ui.prompt.httpproxy.password.title"),
                false);

        password = new char[0];
        fieldsPanel = new JPanel();

        GroupLayout layout = new GroupLayout(fieldsPanel);
        fieldsPanel.setLayout(layout);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        JLabel passwordLabel =
                new JLabel(
                        Constant.messages.getString("network.ui.prompt.httpproxy.password.label"));
        passwordField = new JPasswordField();
        passwordLabel.setLabelFor(passwordField);

        layout.setHorizontalGroup(
                layout.createParallelGroup()
                        .addComponent(passwordLabel)
                        .addComponent(passwordField));

        layout.setVerticalGroup(
                layout.createSequentialGroup()
                        .addComponent(passwordLabel)
                        .addComponent(passwordField));
        initView();
        setConfirmButtonEnabled(true);

        pack();
        setVisible(true);
    }

    @Override
    protected void performAction() {
        password = passwordField.getPassword();
    }

    @Override
    protected JPanel getFieldsPanel() {
        return fieldsPanel;
    }

    @Override
    protected String getConfirmButtonLabel() {
        return Constant.messages.getString("network.ui.prompt.httpproxy.password.button");
    }

    public char[] getPassword() {
        return password;
    }
}
