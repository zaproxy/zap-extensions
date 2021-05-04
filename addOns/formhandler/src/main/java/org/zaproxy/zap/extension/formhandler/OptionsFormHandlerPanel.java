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

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.SortOrder;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.view.AbstractMultipleOptionsTablePanel;

public class OptionsFormHandlerPanel extends AbstractParamPanel {

    private static final long serialVersionUID = 1L;

    private FormHandlerMultipleOptionsPanel fieldsOptionsPanel;

    private OptionsFormHandlerTableModel formHandlerModel = null;

    public OptionsFormHandlerPanel() {
        super();

        this.setName(Constant.messages.getString("formhandler.options.title"));
        this.setLayout(new GridBagLayout());

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.weightx = 1.0;
        gbc.anchor = GridBagConstraints.LINE_START;
        gbc.fill = GridBagConstraints.BOTH;

        this.add(
                new JLabel(Constant.messages.getString("formhandler.options.label.description")),
                gbc);

        fieldsOptionsPanel = new FormHandlerMultipleOptionsPanel(getFormHandlerModel());

        gbc.weighty = 1.0;
        this.add(fieldsOptionsPanel, gbc);
    }

    @Override
    public void initParam(Object obj) {
        OptionsParam optionsParam = (OptionsParam) obj;
        FormHandlerParam param = optionsParam.getParamSet(FormHandlerParam.class);
        getFormHandlerModel().setFields(param.getFields());
        fieldsOptionsPanel.setRemoveWithoutConfirmation(!param.isConfirmRemoveField());
    }

    @Override
    public void saveParam(Object obj) throws Exception {
        OptionsParam optionsParam = (OptionsParam) obj;
        FormHandlerParam formHandlerParam = optionsParam.getParamSet(FormHandlerParam.class);
        formHandlerParam.setFields(getFormHandlerModel().getElements());
        formHandlerParam.setConfirmRemoveField(!fieldsOptionsPanel.isRemoveWithoutConfirmation());
    }

    /**
     * This method initializes FormHandlerTableModel
     *
     * @return OptionsFormHandlerTableModel
     */
    private OptionsFormHandlerTableModel getFormHandlerModel() {
        if (formHandlerModel == null) {
            formHandlerModel = new OptionsFormHandlerTableModel();
        }
        return formHandlerModel;
    }

    @Override
    public String getHelpIndex() {
        return "fhandler";
    }

    private static class FormHandlerMultipleOptionsPanel
            extends AbstractMultipleOptionsTablePanel<FormHandlerParamField> {

        private static final long serialVersionUID = -115340627058929308L;

        private static final String REMOVE_DIALOG_TITLE =
                Constant.messages.getString("formhandler.options.dialog.field.remove.title");
        private static final String REMOVE_DIALOG_TEXT =
                Constant.messages.getString("formhandler.options.dialog.field.remove.text");

        private static final String REMOVE_DIALOG_CONFIRM_BUTTON_LABEL =
                Constant.messages.getString(
                        "formhandler.options.dialog.field.remove.button.confirm");
        private static final String REMOVE_DIALOG_CANCEL_BUTTON_LABEL =
                Constant.messages.getString(
                        "formhandler.options.dialog.field.remove.button.cancel");

        private static final String REMOVE_DIALOG_CHECKBOX_LABEL =
                Constant.messages.getString(
                        "formhandler.options.dialog.field.remove.checkbox.label");

        private DialogAddField addDialog = null;
        private DialogModifyField modifyDialog = null;

        private OptionsFormHandlerTableModel model;

        public FormHandlerMultipleOptionsPanel(OptionsFormHandlerTableModel model) {
            super(model);

            this.model = model;

            getTable().getColumnExt(0).setPreferredWidth(20);
            getTable().setSortOrder(1, SortOrder.ASCENDING);
        }

        @Override
        public FormHandlerParamField showAddDialogue() {
            if (addDialog == null) {
                addDialog = new DialogAddField(View.getSingleton().getOptionsDialog(null));
                addDialog.pack();
            }
            addDialog.setFields(model.getElements());
            addDialog.setVisible(true);

            FormHandlerParamField field = addDialog.getField();
            addDialog.clear();

            return field;
        }

        @Override
        public FormHandlerParamField showModifyDialogue(FormHandlerParamField e) {
            if (modifyDialog == null) {
                modifyDialog = new DialogModifyField(View.getSingleton().getOptionsDialog(null));
                modifyDialog.pack();
            }
            modifyDialog.setFields(model.getElements());
            modifyDialog.setField(e);
            modifyDialog.setVisible(true);

            FormHandlerParamField field = modifyDialog.getField();
            modifyDialog.clear();

            if (!field.equals(e)) {
                return field;
            }

            return null;
        }

        @Override
        public boolean showRemoveDialogue(FormHandlerParamField e) {
            JCheckBox removeWithoutConfirmationCheckBox =
                    new JCheckBox(REMOVE_DIALOG_CHECKBOX_LABEL);
            Object[] messages = {REMOVE_DIALOG_TEXT, " ", removeWithoutConfirmationCheckBox};
            int option =
                    JOptionPane.showOptionDialog(
                            View.getSingleton().getMainFrame(),
                            messages,
                            REMOVE_DIALOG_TITLE,
                            JOptionPane.OK_CANCEL_OPTION,
                            JOptionPane.QUESTION_MESSAGE,
                            null,
                            new String[] {
                                REMOVE_DIALOG_CONFIRM_BUTTON_LABEL,
                                REMOVE_DIALOG_CANCEL_BUTTON_LABEL
                            },
                            null);

            if (option == JOptionPane.OK_OPTION) {
                setRemoveWithoutConfirmation(removeWithoutConfirmationCheckBox.isSelected());

                return true;
            }

            return false;
        }
    }
}
