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

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JOptionPane;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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

    private static final String ADD_MULTIPLE_PAYLOADS_BUTTON =
            Constant.messages.getString(
                    "custompayloads.options.dialog.addMultiplePayload.addPayload.button.name");

    private static final Logger LOG =
            LogManager.getLogger(CustomPayloadsMultipleOptionsTablePanel.class);

    private JButton resetButton;
    private JButton resetButtonId;
    private JButton addMissingDefaultsButton;
    private JButton fileButton;
    private CustomPayloadMultipleOptionsTableModel tableModel;

    public CustomPayloadsMultipleOptionsTablePanel(
            CustomPayloadMultipleOptionsTableModel tableModel) {
        super(tableModel);
        this.tableModel = tableModel;
        addButtonSpacer();
        addMissingDefaultsButton();
        addResetButton();
        addResetIdButton();
        addButtonSpacer();
        addPayloadFileButton();
        getTable().setHorizontalScrollEnabled(true);
    }

    private void addMissingDefaultsButton() {
        addMissingDefaultsButton = new JButton(ADD_MISSING_DEFAULTS_BUTTON);
        addMissingDefaultsButton.addActionListener(e -> tableModel.addMissingDefaultPayloads());
        addButton(addMissingDefaultsButton);
    }

    private void addResetIdButton() {
        resetButtonId = new JButton(RESET_ID_BUTTON);
        resetButtonId.addActionListener(e -> tableModel.resetPayloadIds());
        addButton(resetButtonId);
    }

    private void addResetButton() {
        resetButton = new JButton(RESET_BUTTON);
        resetButton.addActionListener(e -> tableModel.resetToDefaults());
        addButton(resetButton);
    }

    private void addPayloadFileButton() {
        fileButton = new JButton(ADD_MULTIPLE_PAYLOADS_BUTTON);
        fileButton.addActionListener(
                e -> {
                    CustomPayload multiplePayloads = new CustomPayload(-1, true, "", "");
                    CustomMultiplePayloadDialog dialog =
                            new CustomMultiplePayloadDialog(
                                    View.getSingleton().getOptionsDialog(null), multiplePayloads);
                    dialog.pack();
                    dialog.setVisible(true);
                    File file = null;
                    boolean preventDuplicates = false;
                    if (dialog.isSaved()) {
                        file = dialog.getFile();
                        preventDuplicates = dialog.isPreventDuplicates();
                    }
                    if (file == null) {
                        return;
                    }
                    try (BufferedReader txtReader = Files.newBufferedReader(file.toPath())) {
                        String line;
                        ArrayList<CustomPayload> payloads = new ArrayList<>();
                        Set<String> existingPayloads = new HashSet<>();
                        if (preventDuplicates) {
                            tableModel.getPayloadsOfACategory(
                                    existingPayloads, multiplePayloads.getCategory());
                        }
                        while ((line = txtReader.readLine()) != null) {
                            CustomPayload newPayload =
                                    new CustomPayload(multiplePayloads.getCategory(), "");
                            newPayload.setPayload(line);
                            if (preventDuplicates) {
                                if (existingPayloads.add(newPayload.getPayload())) {
                                    payloads.add(newPayload);
                                }
                            } else {
                                payloads.add(newPayload);
                            }
                        }
                        tableModel.addToTable(payloads);

                    } catch (IOException ex) {
                        LOG.warn(ex.getMessage(), ex);
                        JOptionPane.showMessageDialog(
                                this,
                                Constant.messages.getString(
                                        "custompayloads.options.dialog.addMultiplePayload.error.text",
                                        ex.getMessage()),
                                Constant.messages.getString(
                                        "custompayloads.options.dialog.addMultiplePayload.error.title"),
                                JOptionPane.INFORMATION_MESSAGE);
                    }
                });
        addButton(fileButton);
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
