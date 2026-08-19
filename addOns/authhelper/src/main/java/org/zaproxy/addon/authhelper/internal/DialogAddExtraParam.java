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
package org.zaproxy.addon.authhelper.internal;

import java.awt.Dialog;
import java.util.List;
import javax.swing.GroupLayout;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.AbstractFormDialog;

@SuppressWarnings("serial")
class DialogAddExtraParam extends AbstractFormDialog {

    private static final long serialVersionUID = 1L;

    private ZapTextField nameTextField;
    private ZapTextField valueTextField;

    protected ExtraParam param;
    private List<ExtraParam> params;

    public DialogAddExtraParam(Dialog owner) {
        super(
                owner,
                Constant.messages.getString(
                        "authhelper.auth.method.oauth2.extraparams.ui.add.title"));
    }

    protected DialogAddExtraParam(Dialog owner, String title) {
        super(owner, title);
    }

    @Override
    protected JPanel getFieldsPanel() {
        JPanel fieldsPanel = new JPanel();

        GroupLayout layout = new GroupLayout(fieldsPanel);
        fieldsPanel.setLayout(layout);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        JLabel nameLabel =
                new JLabel(
                        Constant.messages.getString(
                                "authhelper.auth.method.oauth2.extraparams.ui.field.name"));
        nameLabel.setLabelFor(getNameTextField());
        JLabel valueLabel =
                new JLabel(
                        Constant.messages.getString(
                                "authhelper.auth.method.oauth2.extraparams.ui.field.value"));
        valueLabel.setLabelFor(getValueTextField());

        layout.setHorizontalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                        .addComponent(nameLabel)
                                        .addComponent(valueLabel))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                        .addComponent(getNameTextField())
                                        .addComponent(getValueTextField())));

        layout.setVerticalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(nameLabel)
                                        .addComponent(getNameTextField()))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(valueLabel)
                                        .addComponent(getValueTextField())));

        setConfirmButtonEnabled(true);

        return fieldsPanel;
    }

    @Override
    protected String getConfirmButtonLabel() {
        return Constant.messages.getString(
                "authhelper.auth.method.oauth2.extraparams.ui.add.button");
    }

    @Override
    protected void init() {
        reset(getNameTextField());
        reset(getValueTextField());
    }

    @Override
    protected boolean validateFields() {
        return validate(null);
    }

    /**
     * Validates the fields.
     *
     * @param oldParam the parameter being modified, to be ignored in the duplicate check, or {@code
     *     null} when adding.
     */
    protected boolean validate(ExtraParam oldParam) {
        String name = getNameTextField().getText().trim();
        if (StringUtils.isEmpty(name)) {
            warn("authhelper.auth.method.oauth2.extraparams.ui.warn.name.empty");
            return false;
        }
        if (params != null
                && params.stream().anyMatch(p -> p != oldParam && p.getName().equals(name))) {
            warn("authhelper.auth.method.oauth2.extraparams.ui.warn.name.duplicate");
            return false;
        }
        return true;
    }

    private void warn(String key) {
        JOptionPane.showMessageDialog(
                this,
                Constant.messages.getString(key),
                Constant.messages.getString(
                        "authhelper.auth.method.oauth2.extraparams.ui.warn.title"),
                JOptionPane.INFORMATION_MESSAGE);
        getNameTextField().requestFocusInWindow();
    }

    @Override
    protected void performAction() {
        param = new ExtraParam(getNameTextField().getText().trim(), getValueTextField().getText());
    }

    @Override
    protected void clearFields() {
        reset(getNameTextField());
        reset(getValueTextField());
    }

    protected static void reset(ZapTextField textField) {
        textField.setText("");
        textField.discardAllEdits();
    }

    protected ZapTextField getNameTextField() {
        if (nameTextField == null) {
            nameTextField = new ZapTextField(25);
        }
        return nameTextField;
    }

    protected ZapTextField getValueTextField() {
        if (valueTextField == null) {
            valueTextField = new ZapTextField(25);
        }
        return valueTextField;
    }

    public ExtraParam getParam() {
        return param;
    }

    public void setParams(List<ExtraParam> params) {
        this.params = params;
    }

    public void clear() {
        this.params = null;
        this.param = null;
    }
}
