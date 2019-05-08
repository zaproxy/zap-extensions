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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.swing.JCheckBox;
import javax.swing.JOptionPane;
import javax.swing.SortOrder;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.fuzz.FuzzerMessageProcessor;
import org.zaproxy.zap.extension.fuzz.FuzzerMessageProcessorUI;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.view.AbstractMultipleOrderedOptionsBaseTablePanel;

public class FuzzerMessageProcessorsTablePanel<
                T1 extends Message, T2 extends FuzzerMessageProcessor<T1>>
        extends AbstractMultipleOrderedOptionsBaseTablePanel<
                FuzzerMessageProcessorTableEntry<T1, T2>> {

    private static final long serialVersionUID = 1225859659521286961L;

    private static final String REMOVE_DIALOG_TITLE =
            Constant.messages.getString("fuzz.fuzzer.dialog.remove.fuzzerMessageProcessor.title");
    private static final String REMOVE_DIALOG_TEXT =
            Constant.messages.getString("fuzz.fuzzer.dialog.remove.fuzzerMessageProcessor.text");

    private static final String REMOVE_DIALOG_CONFIRM_BUTTON_LABEL =
            Constant.messages.getString(
                    "fuzz.fuzzer.dialog.remove.fuzzerMessageProcessor.button.confirm");
    private static final String REMOVE_DIALOG_CANCEL_BUTTON_LABEL =
            Constant.messages.getString(
                    "fuzz.fuzzer.dialog.remove.fuzzerMessageProcessor.button.cancel");

    private static final String REMOVE_DIALOG_CHECKBOX_LABEL =
            Constant.messages.getString(
                    "fuzz.fuzzer.dialog.remove.fuzzerMessageProcessor.checkbox.label");

    private final Dialog owner;
    private final T1 message;
    private final FuzzerMessageProcessors<T1, T2> fuzzerMessageProcessors;

    public FuzzerMessageProcessorsTablePanel(
            Dialog owner, T1 message, FuzzerMessageProcessors<T1, T2> fuzzerMessageProcessors) {
        super(
                new FuzzerMessageProcessorsTableModel<>(
                        fuzzerMessageProcessors.getDefaultProcessors()));

        this.fuzzerMessageProcessors = fuzzerMessageProcessors;

        this.owner = owner;
        this.message = message;

        getTable().setSortOrder(0, SortOrder.ASCENDING);
        getTable().setVisibleRowCount(10);

        getTable().getColumnExt(0).setPrototypeValue(Integer.valueOf(99));
        getTable().getColumnExt(1).setPrototypeValue("Name");
        getTable().getColumnExt(2).setPrototypeValue("Options Description");

        getRemoveWithoutConfirmationCheckBox().setSelected(true);

        addMoveButtons();
    }

    @Override
    protected void selectionChanged(boolean entrySelected) {
        super.selectionChanged(entrySelected);

        if (entrySelected && modifyButton != null) {
            modifyButton.setEnabled(
                    getMultipleOptionsModel().getElement(getSelectedRow()).isMutable());
        }
    }

    public List<T2> getMessageProcessors() {
        if (getModel().getRowCount() == 0) {
            return Collections.emptyList();
        }
        List<T2> messageProcessors = new ArrayList<>(getModel().getRowCount());
        for (FuzzerMessageProcessorTableEntry<T1, T2> entry :
                getMultipleOptionsModel().getElements()) {
            messageProcessors.add(entry.getFuzzerMessageProcessorUI().getFuzzerMessageProcessor());
        }
        return messageProcessors;
    }

    @Override
    public FuzzerMessageProcessorTableEntry<T1, T2> showAddDialogue() {
        AddFuzzerMessageProcessorDialog<T1, T2> addMessageProcessorDialog =
                new AddFuzzerMessageProcessorDialog<>(
                        getParentOwner(), fuzzerMessageProcessors, message);
        addMessageProcessorDialog.pack();
        addMessageProcessorDialog.setVisible(true);

        FuzzerMessageProcessorUI<T1, T2> messageProcessorGeneratorUI =
                addMessageProcessorDialog.getFuzzerMessageProcessorUI();
        if (messageProcessorGeneratorUI == null) {
            return null;
        }

        getMultipleOptionsModel()
                .addElement(
                        new FuzzerMessageProcessorTableEntry<>(
                                getModel().getRowCount() + 1, messageProcessorGeneratorUI));
        updateMoveButtons();

        return null;
    }

    @Override
    public FuzzerMessageProcessorTableEntry<T1, T2> showModifyDialogue(
            FuzzerMessageProcessorTableEntry<T1, T2> e) {
        FuzzerMessageProcessorUI<T1, T2> messageProcessorGeneratorUI =
                showModifyDialogueHelper(e.getFuzzerMessageProcessorUI());

        if (messageProcessorGeneratorUI != null) {
            e.setFuzzerMessageProcessorUI(messageProcessorGeneratorUI);
            return e;
        }
        return null;
    }

    private <T3 extends FuzzerMessageProcessorUI<T1, T2>> T3 showModifyDialogueHelper(
            T3 messageProcessorGeneratorUI) {
        ModifyFuzzerMessageProcessorDialog<T1, T2, T3> modifyMessageProcessorDialog =
                new ModifyFuzzerMessageProcessorDialog<>(
                        getParentOwner(),
                        fuzzerMessageProcessors.getPanel(messageProcessorGeneratorUI),
                        messageProcessorGeneratorUI);
        modifyMessageProcessorDialog.pack();
        modifyMessageProcessorDialog.setVisible(true);

        return modifyMessageProcessorDialog.getFuzzerMessageProcessorUI();
    }

    @Override
    public boolean showRemoveDialogue(
            FuzzerMessageProcessorTableEntry<T1, T2> messageProcessorTableEntry) {
        JCheckBox removeWithoutConfirmationCheckBox = new JCheckBox(REMOVE_DIALOG_CHECKBOX_LABEL);
        Object[] messages = {REMOVE_DIALOG_TEXT, " ", removeWithoutConfirmationCheckBox};
        int option =
                JOptionPane.showOptionDialog(
                        getParentOwner(),
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
            getRemoveWithoutConfirmationCheckBox()
                    .setSelected(removeWithoutConfirmationCheckBox.isSelected());
            return true;
        }

        return false;
    }

    private Dialog getParentOwner() {
        return owner;
    }

    public void reset() {
        getMultipleOptionsModel().clear();
        for (FuzzerMessageProcessorUI<T1, T2> processor :
                fuzzerMessageProcessors.getDefaultProcessors()) {
            getMultipleOptionsModel()
                    .addElement(
                            new FuzzerMessageProcessorTableEntry<>(
                                    getMultipleOptionsModel().getRowCount() + 1, processor));
        }
    }
}
