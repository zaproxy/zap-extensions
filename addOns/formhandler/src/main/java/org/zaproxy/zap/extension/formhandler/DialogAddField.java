/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.formhandler;

import java.awt.Dialog;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import javax.swing.GroupLayout;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.AbstractFormDialog;

@SuppressWarnings("serial")
class DialogAddField extends AbstractFormDialog {

    private static final long serialVersionUID = 4460797449668634319L;
    private static final Logger LOGGER = LogManager.getLogger(DialogAddField.class);

    private static final String DIALOG_TITLE =
            Constant.messages.getString("formhandler.options.dialog.field.add.title");

    private static final String CONFIRM_BUTTON_LABEL =
            Constant.messages.getString("formhandler.options.dialog.field.add.button.confirm");

    private static final String NAME_FIELD_LABEL =
            Constant.messages.getString("formhandler.options.dialog.field.field.label.name");
    private static final String VALUE_FIELD_LABEL =
            Constant.messages.getString("formhandler.options.dialog.field.field.label.value");
    private static final String ENABLED_FIELD_LABEL =
            Constant.messages.getString("formhandler.options.dialog.field.field.label.enabled");
    private static final String REGEX_FIELD_LABEL =
            Constant.messages.getString("formhandler.options.dialog.field.field.label.regex");

    private static final String TITLE_NAME_REPEATED_DIALOG =
            Constant.messages.getString(
                    "formhandler.options.dialog.field.warning.name.repeated.title");
    private static final String TEXT_NAME_REPEATED_DIALOG =
            Constant.messages.getString(
                    "formhandler.options.dialog.field.warning.name.repeated.text");

    private static final String TITLE_BAD_REGEX_DIALOG =
            Constant.messages.getString("formhandler.options.dialog.field.warning.bad.regex.title");
    private static final String TEXT_BAD_REGEX_DIALOG =
            Constant.messages.getString("formhandler.options.dialog.field.warning.bad.regex.text");

    private ZapTextField nameTextField;
    private ZapTextField valueField;
    private JCheckBox enabledCheckBox;
    private JCheckBox regexCheckBox;

    protected FormHandlerParamField field;
    private List<FormHandlerParamField> fields;

    public DialogAddField(Dialog owner) {
        super(owner, DIALOG_TITLE);
    }

    protected DialogAddField(Dialog owner, String title) {
        super(owner, title);
    }

    @Override
    protected JPanel getFieldsPanel() {
        JPanel fieldsPanel = new JPanel();

        GroupLayout layout = new GroupLayout(fieldsPanel);
        fieldsPanel.setLayout(layout);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        JLabel nameLabel = new JLabel(NAME_FIELD_LABEL);
        JLabel valueLabel = new JLabel(VALUE_FIELD_LABEL);
        JLabel enabledLabel = new JLabel(ENABLED_FIELD_LABEL);
        JLabel regexLabel = new JLabel(REGEX_FIELD_LABEL);

        layout.setHorizontalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                        .addComponent(nameLabel)
                                        .addComponent(valueLabel)
                                        .addComponent(enabledLabel)
                                        .addComponent(regexLabel))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                        .addComponent(getNameTextField())
                                        .addComponent(getValueField())
                                        .addComponent(getEnabledCheckBox())
                                        .addComponent(getRegexCheckBox())));

        layout.setVerticalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(nameLabel)
                                        .addComponent(getNameTextField()))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(valueLabel)
                                        .addComponent(getValueField()))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(enabledLabel)
                                        .addComponent(getEnabledCheckBox()))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(regexLabel)
                                        .addComponent(getRegexCheckBox())));

        return fieldsPanel;
    }

    @Override
    protected String getConfirmButtonLabel() {
        return CONFIRM_BUTTON_LABEL;
    }

    @Override
    protected void init() {
        getNameTextField().setText("");
        getValueTextField().setText("");
        getEnabledCheckBox().setSelected(true);
        getRegexCheckBox().setSelected(false);
        field = null;
    }

    /*
     * Confirms the fields do not already exist
     */
    @Override
    protected boolean validateFields() {
        String name = getNameTextField().getText();
        String fieldName = getRegexCheckBox().isSelected() ? name : name.toLowerCase(Locale.ROOT);
        if (getRegexCheckBox().isSelected()) {
            try {
                Pattern.compile(fieldName);
            } catch (PatternSyntaxException pse) {
                LOGGER.debug("Invalid regex.", pse);
                showBadRegexDialog();
                return false;
            }
        }
        for (FormHandlerParamField t : fields) {
            if (fieldName.equals(t.getName())) {
                showNameRepeatedDialog();
                getNameTextField().requestFocusInWindow();
                return false;
            }
        }

        return true;
    }

    protected void showNameRepeatedDialog() {
        JOptionPane.showMessageDialog(
                this,
                TEXT_NAME_REPEATED_DIALOG,
                TITLE_NAME_REPEATED_DIALOG,
                JOptionPane.INFORMATION_MESSAGE);
    }

    protected void showBadRegexDialog() {
        JOptionPane.showMessageDialog(
                this, TEXT_BAD_REGEX_DIALOG, TITLE_BAD_REGEX_DIALOG, JOptionPane.WARNING_MESSAGE);
    }

    /**
     * When the Add button is clicked, create a new field. This field will be created with the name,
     * value and enabled input by the user. The name will always be lower case.
     */
    @Override
    protected void performAction() {
        field =
                new FormHandlerParamField(
                        getNameTextField().getText(),
                        getValueTextField().getText(),
                        getEnabledCheckBox().isSelected(),
                        getRegexCheckBox().isSelected());
    }

    @Override
    protected void clearFields() {
        getNameTextField().setText("");
        getNameTextField().discardAllEdits();
    }

    public FormHandlerParamField getField() {
        return field;
    }

    protected ZapTextField getNameTextField() {
        if (nameTextField == null) {
            nameTextField = new ZapTextField(25);
            nameTextField
                    .getDocument()
                    .addDocumentListener(
                            new DocumentListener() {

                                @Override
                                public void removeUpdate(DocumentEvent e) {
                                    checkAndEnableConfirmButton();
                                }

                                @Override
                                public void insertUpdate(DocumentEvent e) {
                                    checkAndEnableConfirmButton();
                                }

                                @Override
                                public void changedUpdate(DocumentEvent e) {
                                    checkAndEnableConfirmButton();
                                }

                                private void checkAndEnableConfirmButton() {
                                    setConfirmButtonEnabled(
                                            getNameTextField().getDocument().getLength() > 0);
                                }
                            });
        }

        return nameTextField;
    }

    protected ZapTextField getValueTextField() {
        if (valueField == null) {
            valueField = new ZapTextField(25);
        }

        return valueField;
    }

    protected JComponent getValueField() {
        return getValueTextField();
    }

    protected JCheckBox getEnabledCheckBox() {
        if (enabledCheckBox == null) {
            enabledCheckBox = new JCheckBox();
        }

        return enabledCheckBox;
    }

    protected JCheckBox getRegexCheckBox() {
        if (regexCheckBox == null) {
            regexCheckBox = new JCheckBox();
        }

        return regexCheckBox;
    }

    public void setFields(List<FormHandlerParamField> fields) {
        this.fields = fields;
    }

    public void clear() {
        this.fields = null;
        this.field = null;
    }
}
