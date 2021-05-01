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
import javax.swing.GroupLayout;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.SortOrder;
import org.apache.commons.lang.StringUtils;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.fuzz.payloads.Payload;
import org.zaproxy.zap.extension.fuzz.payloads.processor.PayloadProcessor;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.PayloadProcessorUI;
import org.zaproxy.zap.model.MessageLocation;
import org.zaproxy.zap.utils.ResettableAutoCloseableIterator;
import org.zaproxy.zap.view.AbstractFormDialog;
import org.zaproxy.zap.view.AbstractMultipleOrderedOptionsBaseTablePanel;

public class ProcessorsMessageLocationDialog extends AbstractFormDialog {

    protected static final long serialVersionUID = -7609757285865562636L;

    private static final String CONFIRM_BUTTON_LABEL =
            Constant.messages.getString(
                    "fuzz.fuzzer.dialog.messagelocations.dialog.processors.button.confirm");

    private static final String REMOVE_DIALOG_TITLE =
            Constant.messages.getString(
                    "fuzz.fuzzer.dialog.messagelocations.dialog.remove.processor.title");
    private static final String REMOVE_DIALOG_TEXT =
            Constant.messages.getString(
                    "fuzz.fuzzer.dialog.messagelocations.dialog.remove.processor.text");

    private static final String REMOVE_DIALOG_CONFIRM_BUTTON_LABEL =
            Constant.messages.getString(
                    "fuzz.fuzzer.dialog.messagelocations.dialog.remove.processor.button.confirm");
    private static final String REMOVE_DIALOG_CANCEL_BUTTON_LABEL =
            Constant.messages.getString(
                    "fuzz.fuzzer.dialog.messagelocations.dialog.remove.processor.button.cancel");

    private static final String REMOVE_DIALOG_CHECKBOX_LABEL =
            Constant.messages.getString(
                    "fuzz.fuzzer.dialog.messagelocations.dialog.remove.processor.checkbox.label");

    private ProcessorsTablePanel processorsTablePanel;

    private PayloadProcessorsContainer processorsUIHandlers;

    private List<PayloadProcessorTableEntry> processors;

    private ResettableAutoCloseableIterator<? extends Payload> payloads;

    private MessageLocation messageLocation;
    private JLabel messageLocationLabel;
    private JLabel messageLocationValueLabel;

    public ProcessorsMessageLocationDialog(
            Dialog parent, PayloadProcessorsContainer processorsUIHandlers) {
        super(
                parent,
                Constant.messages.getString(
                        "fuzz.fuzzer.dialog.messagelocations.dialog.processors.title"),
                false);

        this.processors = Collections.emptyList();
        this.processorsUIHandlers = processorsUIHandlers;
        this.processorsTablePanel = new ProcessorsTablePanel();

        setConfirmButtonEnabled(true);

        initView();
        pack();
    }

    @Override
    protected JPanel getFieldsPanel() {
        JPanel fieldsPanel = new JPanel();

        GroupLayout layout = new GroupLayout(fieldsPanel);
        fieldsPanel.setLayout(layout);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        JLabel locationLabel =
                new JLabel(
                        Constant.messages.getString(
                                "fuzz.fuzzer.dialog.messagelocations.dialog.processors.location.label"));
        messageLocationLabel = new JLabel();
        JLabel valueLabel =
                new JLabel(
                        Constant.messages.getString(
                                "fuzz.fuzzer.dialog.messagelocations.dialog.processors.value.label"));
        messageLocationValueLabel = new JLabel();
        JLabel payloadsLabel =
                new JLabel(
                        Constant.messages.getString(
                                "fuzz.fuzzer.dialog.messagelocations.dialog.processors.processors.label"));

        layout.setHorizontalGroup(
                layout.createParallelGroup()
                        .addGroup(
                                layout.createSequentialGroup()
                                        .addComponent(locationLabel)
                                        .addComponent(messageLocationLabel))
                        .addGroup(
                                layout.createSequentialGroup()
                                        .addComponent(valueLabel)
                                        .addComponent(messageLocationValueLabel))
                        .addComponent(payloadsLabel)
                        .addComponent(processorsTablePanel));

        layout.setVerticalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(locationLabel)
                                        .addComponent(messageLocationLabel))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(valueLabel)
                                        .addComponent(messageLocationValueLabel))
                        .addComponent(payloadsLabel)
                        .addComponent(processorsTablePanel));

        return fieldsPanel;
    }

    @Override
    protected String getConfirmButtonLabel() {
        return CONFIRM_BUTTON_LABEL;
    }

    @Override
    protected void clearFields() {
        messageLocation = null;
        payloads = null;
        processorsTablePanel.setProcessors(Collections.<PayloadProcessorTableEntry>emptyList());
    }

    @Override
    protected void performAction() {
        processors = processorsTablePanel.getProcessors();
    }

    public List<PayloadProcessorTableEntry> getProcessors() {
        return processors;
    }

    private class ProcessorsTablePanel
            extends AbstractMultipleOrderedOptionsBaseTablePanel<PayloadProcessorTableEntry> {

        private static final long serialVersionUID = 779189100799721039L;

        public ProcessorsTablePanel() {
            super(new ProcessorsTableModel());

            getTable().setSortOrder(0, SortOrder.ASCENDING);
            getTable().setVisibleRowCount(10);

            getTable().getColumnExt(0).setPrototypeValue(Integer.valueOf(99));
            getTable().getColumnExt(1).setPrototypeValue("Processor Type");
            getTable()
                    .getColumnExt(2)
                    .setPrototypeValue("Description of Processors which is larger than the type.");

            getRemoveWithoutConfirmationCheckBox().setSelected(true);

            addMoveButtons();
        }

        public void setProcessors(List<PayloadProcessorTableEntry> processors) {
            getMultipleOptionsModel().setProcessors(processors);
        }

        @Override
        protected ProcessorsTableModel getMultipleOptionsModel() {
            return (ProcessorsTableModel) super.getMultipleOptionsModel();
        }

        public List<PayloadProcessorTableEntry> getProcessors() {
            return getMultipleOptionsModel().getElements();
        }

        @Override
        protected void selectionChanged(boolean entrySelected) {
            super.selectionChanged(entrySelected);

            if (entrySelected && modifyButton != null) {
                modifyButton.setEnabled(
                        getMultipleOptionsModel().getElement(getSelectedRow()).isMutable());
            }
        }

        @Override
        public PayloadProcessorTableEntry showAddDialogue() {
            AddProcessorDialog addProcessorDialog =
                    new AddProcessorDialog(
                            ProcessorsMessageLocationDialog.this,
                            processorsUIHandlers,
                            messageLocation,
                            getProcessedPayloads());
            addProcessorDialog.pack();
            addProcessorDialog.setVisible(true);

            PayloadProcessorUI<?, ?> processorUI = addProcessorDialog.getPayloadProcessorUI();
            if (processorUI == null) {
                return null;
            }

            getMultipleOptionsModel()
                    .addElement(
                            new PayloadProcessorTableEntry(
                                    getModel().getRowCount() + 1, processorUI));

            updateMoveButtons();

            return null;
        }

        @Override
        public PayloadProcessorTableEntry showModifyDialogue(PayloadProcessorTableEntry e) {
            PayloadProcessorUI<?, ?> processorUI =
                    showModifyDialogueImpl(e, (PayloadProcessorUI) e.getPayloadProcessorUI());

            if (processorUI != null) {
                e.setPayloadProcessorUI(processorUI);
                return e;
            }
            return null;
        }

        private <
                        T0 extends Payload,
                        T1 extends PayloadProcessor<T0>,
                        T2 extends PayloadProcessorUI<T0, T1>>
                T2 showModifyDialogueImpl(PayloadProcessorTableEntry e, T2 payloadGeneratorUI) {
            ModifyProcessorDialog<T0, T1, T2> modifyProcessorDialog =
                    new ModifyProcessorDialog<>(
                            ProcessorsMessageLocationDialog.this,
                            processorsUIHandlers.getPanel(payloadGeneratorUI),
                            payloadGeneratorUI,
                            getProcessedPayloads(e.getOrder() - 1));
            modifyProcessorDialog.pack();
            modifyProcessorDialog.setVisible(true);

            return modifyProcessorDialog.getPayloadProcessorUI();
        }

        @Override
        public boolean showRemoveDialogue(PayloadProcessorTableEntry processorTableEntry) {
            JCheckBox removeWithoutConfirmationCheckBox =
                    new JCheckBox(REMOVE_DIALOG_CHECKBOX_LABEL);
            Object[] messages = {REMOVE_DIALOG_TEXT, " ", removeWithoutConfirmationCheckBox};
            int option =
                    JOptionPane.showOptionDialog(
                            ProcessorsMessageLocationDialog.this,
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
    }

    public void setMessageLocation(MessageLocation messageLocation) {
        this.messageLocation = messageLocation;
        messageLocationLabel.setText(messageLocation.getDescription());
        messageLocationValueLabel.setText(StringUtils.abbreviate(messageLocation.getValue(), 150));
        getContentPane().revalidate();
    }

    public void setPayloadProcessors(List<PayloadProcessorTableEntry> processors) {
        this.processors = processors;
        this.processorsTablePanel.setProcessors(processors);
    }

    public void setPayloads(ResettableAutoCloseableIterator<? extends Payload> payloads) {
        this.payloads = payloads;
    }

    private ResettableAutoCloseableIterator<Payload> getProcessedPayloads() {
        return getProcessedPayloads(-1);
    }

    private ResettableAutoCloseableIterator<Payload> getProcessedPayloads(int numberOfProcessors) {
        List<PayloadProcessor<Payload>> currentProcessors = new ArrayList<>();
        int count = 0;
        for (PayloadProcessorTableEntry processorEntry : processorsTablePanel.getProcessors()) {
            if (numberOfProcessors > -1 && count >= numberOfProcessors) {
                break;
            }
            currentProcessors.add(
                    (PayloadProcessor<Payload>)
                            processorEntry.getPayloadProcessorUI().getPayloadProcessor());
            count++;
        }
        return new PayloadsProcessedIterator(payloads, currentProcessors);
    }
}
