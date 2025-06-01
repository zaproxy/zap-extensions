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
import javax.swing.JPanel;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.network.internal.server.http.Alias;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.AbstractFormDialog;

@SuppressWarnings("serial")
public class AddAliasDialog extends AbstractFormDialog {

    private static final long serialVersionUID = 1L;

    protected final JPanel fieldsPanel;
    protected final ZapTextField nameTextField;
    protected final JCheckBox enabledCheckBox;

    protected Alias alias;

    public AddAliasDialog(Dialog owner) {
        this(owner, Constant.messages.getString("network.ui.options.alias.add.title"));
    }

    protected AddAliasDialog(Dialog owner, String title) {
        super(owner, title, false);

        fieldsPanel = new JPanel();

        GroupLayout layout = new GroupLayout(fieldsPanel);
        fieldsPanel.setLayout(layout);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        JLabel authorityLabel =
                new JLabel(Constant.messages.getString("network.ui.options.alias.add.field.name"));
        nameTextField = new ZapTextField(25);
        nameTextField.getDocument().addDocumentListener(new EnableButtonDocumentListener());
        authorityLabel.setLabelFor(nameTextField);

        JLabel enabledLabel =
                new JLabel(
                        Constant.messages.getString("network.ui.options.alias.add.field.enabled"));
        enabledCheckBox = new JCheckBox();
        enabledLabel.setLabelFor(enabledCheckBox);

        layout.setHorizontalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                        .addComponent(authorityLabel)
                                        .addComponent(enabledLabel))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                        .addComponent(nameTextField)
                                        .addComponent(enabledCheckBox)));

        layout.setVerticalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(authorityLabel)
                                        .addComponent(nameTextField))
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
        return Constant.messages.getString("network.ui.options.alias.add.button");
    }

    @Override
    protected void init() {
        nameTextField.setText("");
        nameTextField.discardAllEdits();
        enabledCheckBox.setSelected(true);
        alias = null;
    }

    @Override
    protected void performAction() {
        alias = new Alias(nameTextField.getText(), enabledCheckBox.isSelected());
    }

    public Alias getAlias() {
        Alias alias = this.alias;
        this.alias = null;
        return alias;
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
