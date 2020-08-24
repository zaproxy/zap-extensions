/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.custompayloads;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JOptionPane;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.view.AbstractMultipleOptionsTablePanel;

public class CustomPayloadsMultipleOptionsTablePanel
        extends AbstractMultipleOptionsTablePanel<CustomPayload> {

    private static final long serialVersionUID = 1L;
    private static final String REMOVE_DIALOG_TITLE =
            Constant.messages.getString("custompayloads.options.dialog.remove.title");
    private static final String REMOVE_DIALOG_TEXT =
            Constant.messages.getString("custompayloads.options.dialog.remove.text");

    private static final String RESET_BUTTON =
            Constant.messages.getString("custompayloads.options.button.reset");
    private static final String RESET_ID_BUTTON =
            Constant.messages.getString("custompayloads.options.button.resetIds");
    private static final String ADD_MISSING_DEFAULTS_BUTTON =
            Constant.messages.getString("custompayloads.options.button.addMissingDefaults");

    private static final String REMOVE_DIALOG_CONFIRM_BUTTON_LABEL =
            Constant.messages.getString("custompayloads.options.dialog.remove.button.confirm");
    private static final String REMOVE_DIALOG_CANCEL_BUTTON_LABEL =
            Constant.messages.getString("custompayloads.options.dialog.remove.button.cancel");

    private static final String REMOVE_DIALOG_CHECKBOX_LABEL =
            Constant.messages.getString("custompayloads.options.dialog.remove.label");
    private JButton resetButton;
    private JButton resetButtonId;
    private JButton addMissingDefaultsButton;
    private CustomPayloadMultipleOptionsTableModel tableModel;

    public CustomPayloadsMultipleOptionsTablePanel(
            CustomPayloadMultipleOptionsTableModel tableModel) {
        super(tableModel);
        this.tableModel = tableModel;
        addButtonSpacer();
        addMissingDefaultsButton();
        addResetButton();
        addResetIdButton();
        getTable().setHorizontalScrollEnabled(true);
    }

    private void addMissingDefaultsButton() {
        addMissingDefaultsButton = new JButton(ADD_MISSING_DEFAULTS_BUTTON);
        addMissingDefaultsButton.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent evt) {
                        tableModel.addMissingDefaultPayloads();
                    }
                });
        addButton(addMissingDefaultsButton);
    }

    private void addResetIdButton() {
        resetButtonId = new JButton(RESET_ID_BUTTON);
        resetButtonId.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent evt) {
                        tableModel.resetPayloadIds();
                    }
                });
        addButton(resetButtonId);
    }

    private void addResetButton() {
        resetButton = new JButton(RESET_BUTTON);
        resetButton.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent evt) {
                        tableModel.resetToDefaults();
                    }
                });
        addButton(resetButton);
    }

    @Override
    public CustomPayload showAddDialogue() {
        CustomPayload payload = new CustomPayload(-1, true, "", "");
        if (showDialog(payload)) {
            tableModel.setNextIdToPayload(payload);
            return payload;
        }
        return null;
    }

    private boolean showDialog(CustomPayload payload) {
        CustomPayloadDialog dialog =
                new CustomPayloadDialog(
                        View.getSingleton().getOptionsDialog(null),
                        "custompayloads.options.dialog.title",
                        payload);
        dialog.pack();
        dialog.setVisible(true);
        return dialog.isSaved();
    }

    @Override
    public CustomPayload showModifyDialogue(CustomPayload payload) {
        showDialog(payload);
        return payload;
    }

    @Override
    public boolean showRemoveDialogue(CustomPayload payload) {
        getTable().packAll();
        JCheckBox removeWithoutConfirmationCheckBox = new JCheckBox(REMOVE_DIALOG_CHECKBOX_LABEL);
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
                            REMOVE_DIALOG_CONFIRM_BUTTON_LABEL, REMOVE_DIALOG_CANCEL_BUTTON_LABEL
                        },
                        null);

        if (option == JOptionPane.OK_OPTION) {
            setRemoveWithoutConfirmation(removeWithoutConfirmationCheckBox.isSelected());
            return true;
        }

        return false;
    }
}
