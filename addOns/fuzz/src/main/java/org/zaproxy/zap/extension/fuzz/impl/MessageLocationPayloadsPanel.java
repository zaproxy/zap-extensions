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

import java.awt.Window;
import java.util.List;
import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SortOrder;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.fuzz.payloads.Payload;
import org.zaproxy.zap.extension.fuzz.payloads.generator.PayloadGenerator;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUI;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.PayloadProcessorUIHandlersRegistry;
import org.zaproxy.zap.model.MessageLocation;
import org.zaproxy.zap.utils.ResettableAutoCloseableIterator;
import org.zaproxy.zap.utils.StringUIUtils;
import org.zaproxy.zap.view.AbstractMultipleOrderedOptionsBaseTablePanel;

public class MessageLocationPayloadsPanel extends JPanel {

    private static final long serialVersionUID = 693504188920055070L;

    private static final String REMOVE_DIALOG_TITLE =
            Constant.messages.getString("fuzz.fuzzer.dialog.remove.payload.title");
    private static final String REMOVE_DIALOG_TEXT =
            Constant.messages.getString("fuzz.fuzzer.dialog.remove.payload.text");

    private static final String REMOVE_DIALOG_CONFIRM_BUTTON_LABEL =
            Constant.messages.getString("fuzz.fuzzer.dialog.remove.payload.button.confirm");
    private static final String REMOVE_DIALOG_CANCEL_BUTTON_LABEL =
            Constant.messages.getString("fuzz.fuzzer.dialog.remove.payload.button.cancel");

    private static final String REMOVE_DIALOG_CHECKBOX_LABEL =
            Constant.messages.getString("fuzz.fuzzer.dialog.remove.payload.checkbox.label");

    private final Window parent;

    private MessageLocation messageLocation;
    private PayloadsTablePanel payloadsTablePanel;

    private PayloadGeneratorsContainer payloadGeneratorsUIHandlers;

    private ProcessorsPayloadDialog processorsDialog;

    private PayloadsChangedListener payloadsChangedListener;

    public MessageLocationPayloadsPanel(
            Window parent,
            MessageLocation messageLocation,
            List<PayloadTableEntry> payloads,
            PayloadGeneratorsContainer payloadGeneratorsUIHandlers) {
        this.parent = parent;
        this.payloadGeneratorsUIHandlers = payloadGeneratorsUIHandlers;
        this.messageLocation = messageLocation;
        this.payloadsTablePanel = new PayloadsTablePanel(payloads);

        GroupLayout layout = new GroupLayout(this);
        setLayout(layout);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        JLabel locationLabel =
                new JLabel(
                        Constant.messages.getString(
                                "fuzz.fuzzer.dialog.payloads.messagelocation.label.location"));
        JLabel messageLocationLabel = new JLabel(messageLocation.getDescription());
        JLabel valueLabel =
                new JLabel(
                        Constant.messages.getString(
                                "fuzz.fuzzer.dialog.payloads.messagelocation.label.value"));

        JComponent messageLocationValue;
        String value = messageLocation.getValue();
        if (value.length() > 100) {
            JTextArea messageLocationValueTextArea =
                    new JTextArea(StringUIUtils.addVisibleNewLineChars(value));
            messageLocationValueTextArea.setColumns(10);
            messageLocationValueTextArea.setRows(5);
            messageLocationValueTextArea.setEditable(false);

            JScrollPane messageLocationValueScrollPane =
                    new JScrollPane(messageLocationValueTextArea);
            messageLocationValue = messageLocationValueScrollPane;
        } else {
            JLabel messageLocationValueLabel =
                    new JLabel(
                            StringUIUtils.containsNewLineChars(value)
                                    ? StringUIUtils.replaceWithVisibleWhiteSpaceChars(value)
                                    : value);
            messageLocationValue = messageLocationValueLabel;
        }

        JLabel payloadsLabel =
                new JLabel(
                        Constant.messages.getString("fuzz.fuzzer.dialog.payloads.payloads.label"));

        layout.setHorizontalGroup(
                layout.createParallelGroup()
                        .addGroup(
                                layout.createSequentialGroup()
                                        .addComponent(locationLabel)
                                        .addComponent(messageLocationLabel))
                        .addGroup(
                                layout.createSequentialGroup()
                                        .addComponent(valueLabel)
                                        .addComponent(messageLocationValue))
                        .addComponent(payloadsLabel)
                        .addComponent(payloadsTablePanel));

        layout.setVerticalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(locationLabel)
                                        .addComponent(messageLocationLabel))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(valueLabel)
                                        .addComponent(messageLocationValue))
                        .addComponent(payloadsLabel)
                        .addComponent(payloadsTablePanel));
    }

    public void clear() {
        if (processorsDialog != null) {
            processorsDialog.dispose();
        }
    }

    public List<PayloadTableEntry> getPayloads() {
        return payloadsTablePanel.getPayloads();
    }

    public void setPayloadsChangedListener(PayloadsChangedListener listener) {
        payloadsChangedListener = listener;
    }

    public boolean hasPayloads() {
        return payloadsTablePanel.hasPayloads();
    }

    private class PayloadsTablePanel
            extends AbstractMultipleOrderedOptionsBaseTablePanel<PayloadTableEntry> {

        private static final long serialVersionUID = 779189100799721039L;

        private final JButton processorsButton;

        public PayloadsTablePanel(List<PayloadTableEntry> payloads) {
            super(new PayloadsTableModel(payloads));

            getTable().setSortOrder(0, SortOrder.ASCENDING);
            getTable().setVisibleRowCount(10);

            getTable().getColumnExt(0).setPrototypeValue(Integer.valueOf(99));
            getTable().getColumnExt(1).setPrototypeValue("Payload Type");
            getTable()
                    .getColumnExt(2)
                    .setPrototypeValue("Value Of Payload which might be very very large");
            getTable().getColumnExt(3).setPrototypeValue("7 Processors");

            getRemoveWithoutConfirmationCheckBox().setSelected(true);

            addButtonSpacer();

            processorsButton =
                    new JButton(
                            Constant.messages.getString(
                                    "fuzz.fuzzer.dialog.payloads.button.processors"));
            processorsButton.setToolTipText(
                    Constant.messages.getString(
                            "fuzz.fuzzer.dialog.payloads.button.processors.tooltip"));
            processorsButton.setEnabled(false);
            processorsButton.addActionListener(
                    e -> {
                        if (processorsDialog == null) {
                            processorsDialog =
                                    new ProcessorsPayloadDialog(
                                            parent,
                                            new PayloadProcessorsContainer(
                                                    PayloadProcessorUIHandlersRegistry.getInstance()
                                                            .getProcessorUIHandlers(),
                                                    PayloadProcessorUIHandlersRegistry.getInstance()
                                                            .getNameDefaultPayloadProcessor()));
                            processorsDialog.pack();
                        }
                        int row = getSelectedRow();
                        PayloadTableEntry payloadTableEntry =
                                getMultipleOptionsModel().getElement(row);

                        processorsDialog.setMessageLocation(messageLocation);
                        processorsDialog.setPayloadProcessors(
                                payloadTableEntry.getPayloadProcessors());
                        processorsDialog.setPayloads(
                                (ResettableAutoCloseableIterator<Payload>)
                                        payloadTableEntry
                                                .getPayloadGeneratorUI()
                                                .getPayloadGenerator()
                                                .iterator());
                        processorsDialog.setVisible(true);

                        payloadTableEntry.setPayloadProcessors(processorsDialog.getProcessors());
                        getMultipleOptionsModel().fireTableRowsUpdated(row, row);
                    });
            addButton(processorsButton);

            addMoveButtons();
        }

        public boolean hasPayloads() {
            return getMultipleOptionsModel().getRowCount() != 0;
        }

        public List<PayloadTableEntry> getPayloads() {
            return getMultipleOptionsModel().getElements();
        }

        @Override
        protected void selectionChanged(boolean entrySelected) {
            super.selectionChanged(entrySelected);

            processorsButton.setEnabled(entrySelected);
        }

        @Override
        public PayloadTableEntry showAddDialogue() {
            AddPayloadDialog addPayloadDialog =
                    new AddPayloadDialog(parent, payloadGeneratorsUIHandlers, messageLocation);
            addPayloadDialog.pack();
            addPayloadDialog.setVisible(true);

            PayloadGeneratorUI<?, ?> payloadGeneratorUI = addPayloadDialog.getPayloadGeneratorUI();
            if (payloadGeneratorUI == null) {
                return null;
            }

            getMultipleOptionsModel()
                    .addElement(
                            new PayloadTableEntry(
                                    getModel().getRowCount() + 1, payloadGeneratorUI));
            updateMoveButtons();

            if (payloadsChangedListener != null) {
                payloadsChangedListener.payloadAdded(getModel().getRowCount());
            }
            return null;
        }

        @Override
        public PayloadTableEntry showModifyDialogue(PayloadTableEntry e) {
            PayloadGeneratorUI<?, ?> payloadGeneratorUI =
                    showModifyDialogueHelper((PayloadGeneratorUI) e.getPayloadGeneratorUI());

            if (payloadGeneratorUI != null) {
                e.setPayloadGeneratorUI(payloadGeneratorUI);
                return e;
            }
            return null;
        }

        private <
                        T extends Payload,
                        T2 extends PayloadGenerator<T>,
                        T3 extends PayloadGeneratorUI<T, T2>>
                T3 showModifyDialogueHelper(T3 payloadGeneratorUI) {
            ModifyPayloadDialog<T, T2, T3> modifyPayloadDialog =
                    new ModifyPayloadDialog<>(
                            parent,
                            payloadGeneratorsUIHandlers.getPanel(payloadGeneratorUI),
                            payloadGeneratorUI);
            modifyPayloadDialog.pack();
            modifyPayloadDialog.setVisible(true);

            return modifyPayloadDialog.getPayloadGeneratorUI();
        }

        @Override
        public boolean showRemoveDialogue(PayloadTableEntry payloadTableEntry) {
            if (!getRemoveWithoutConfirmationCheckBox().isSelected()) {
                if (!showRemoveDialogueImpl(payloadTableEntry)) {
                    return false;
                }
            }

            if (payloadsChangedListener != null) {
                payloadsChangedListener.payloadRemoved(getModel().getRowCount() - 1);
            }
            return true;
        }

        protected boolean showRemoveDialogueImpl(PayloadTableEntry payloadTableEntry) {
            JCheckBox removeWithoutConfirmationCheckBox =
                    new JCheckBox(REMOVE_DIALOG_CHECKBOX_LABEL);
            Object[] messages = {REMOVE_DIALOG_TEXT, " ", removeWithoutConfirmationCheckBox};
            int option =
                    JOptionPane.showOptionDialog(
                            parent,
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
                getRemoveWithoutConfirmationCheckBox()
                        .setSelected(removeWithoutConfirmationCheckBox.isSelected());
                return true;
            }

            return false;
        }

        @Override
        public boolean isRemoveWithoutConfirmation() {
            // Force base class to call the method showRemoveDialogue(PayloadTableEntry) so the
            // state of the dialogue can be changed before deleting the entries
            return false;
        }
    }

    public static interface PayloadsChangedListener {

        void payloadAdded(int currentNumberOfPayloads);

        void payloadRemoved(int currentNumberOfPayloads);
    }
}
