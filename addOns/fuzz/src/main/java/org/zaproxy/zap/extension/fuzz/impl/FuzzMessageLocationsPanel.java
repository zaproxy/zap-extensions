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
import javax.swing.JButton;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.fuzz.payloads.Payload;
import org.zaproxy.zap.extension.fuzz.payloads.PayloadGeneratorMessageLocation;
import org.zaproxy.zap.extension.fuzz.payloads.generator.CompositePayloadGenerator;
import org.zaproxy.zap.extension.fuzz.payloads.generator.PayloadGenerator;
import org.zaproxy.zap.extension.fuzz.payloads.generator.ProcessedPayloadGenerator;
import org.zaproxy.zap.extension.fuzz.payloads.processor.PayloadProcessor;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.PayloadProcessorUIHandlersRegistry;
import org.zaproxy.zap.model.MessageLocation;
import org.zaproxy.zap.utils.ResettableAutoCloseableIterator;
import org.zaproxy.zap.view.messagelocation.AbstractMessageLocationsPanel;
import org.zaproxy.zap.view.messagelocation.MessageLocationHighlight;
import org.zaproxy.zap.view.messagelocation.MessageLocationsTableModel;

public class FuzzMessageLocationsPanel
        extends AbstractMessageLocationsPanel<
                FuzzLocationTableEntry, MessageLocationsTableModel<FuzzLocationTableEntry>> {

    protected static final long serialVersionUID = -7609757285865562636L;

    private PayloadGeneratorsContainer payloadGeneratorsUIHandlers;

    private final JButton processorsButton;
    private final JButton payloadsButton;

    private ProcessorsMessageLocationDialog processorsDialog;

    public FuzzMessageLocationsPanel(
            Dialog owner,
            FuzzMessagePanel fuzzMessagePanel,
            PayloadGeneratorsContainer payloadGeneratorsUIHandlers) {
        super(owner, fuzzMessagePanel, new FuzzLocationsTableModel(), false);

        this.payloadGeneratorsUIHandlers = payloadGeneratorsUIHandlers;

        addButtonSpacer();

        payloadsButton =
                new JButton(
                        Constant.messages.getString(
                                "fuzz.fuzzer.dialog.messagelocations.button.payloads.label"));
        payloadsButton.setToolTipText(
                Constant.messages.getString(
                        "fuzz.fuzzer.dialog.messagelocations.button.processors.tooltip"));
        payloadsButton.addActionListener(
                e -> {
                    int row = getSelectedRow();
                    FuzzLocationTableEntry entry = getMultipleOptionsModel().getElement(row);

                    PayloadsDialog a =
                            new PayloadsDialog(
                                    getParentOwner(),
                                    entry.getLocation(),
                                    entry.getPayloads(),
                                    FuzzMessageLocationsPanel.this.payloadGeneratorsUIHandlers);
                    a.setVisible(true);

                    List<PayloadTableEntry> payloads = a.getPayloads();
                    if (payloads != null) {
                        entry.setPayloads(payloads);
                        getMultipleOptionsModel().fireTableRowsUpdated(row, row);
                    }
                });
        payloadsButton.setEnabled(false);
        addButton(payloadsButton);

        addButtonSpacer();

        processorsButton =
                new JButton(
                        Constant.messages.getString(
                                "fuzz.fuzzer.dialog.messagelocations.button.processors.label"));
        processorsButton.setToolTipText(
                Constant.messages.getString(
                        "fuzz.fuzzer.dialog.messagelocations.button.processors.tooltip"));
        processorsButton.addActionListener(
                e -> {
                    if (processorsDialog == null) {
                        processorsDialog =
                                new ProcessorsMessageLocationDialog(
                                        getParentOwner(),
                                        new PayloadProcessorsContainer(
                                                PayloadProcessorUIHandlersRegistry.getInstance()
                                                        .getProcessorUIHandlers(),
                                                PayloadProcessorUIHandlersRegistry.getInstance()
                                                        .getNameDefaultPayloadProcessor()));
                        processorsDialog.pack();
                    }
                    int row = getSelectedRow();
                    FuzzLocationTableEntry locationEntry =
                            getMultipleOptionsModel().getElement(row);

                    processorsDialog.setMessageLocation(locationEntry.getLocation());
                    processorsDialog.setPayloadProcessors(locationEntry.getProcessors());
                    processorsDialog.setPayloads(getPayloads(locationEntry));
                    processorsDialog.setVisible(true);

                    locationEntry.setProcessors(processorsDialog.getProcessors());
                    getMultipleOptionsModel().fireTableRowsUpdated(row, row);
                });
        processorsButton.setEnabled(false);
        addButton(processorsButton);
    }

    @Override
    protected void selectionChanged(boolean entrySelected) {
        super.selectionChanged(entrySelected);

        payloadsButton.setEnabled(entrySelected);
        processorsButton.setEnabled(entrySelected);
    }

    @Override
    protected FuzzLocationTableEntry createMessageLocationTableEntry(
            boolean buttonAddedLocation,
            MessageLocation messageLocation,
            MessageLocationHighlight highlight,
            MessageLocationHighlight highlightReference) {
        List<PayloadTableEntry> payloads;
        if (buttonAddedLocation) {
            PayloadsDialog a =
                    new PayloadsDialog(
                            getParentOwner(),
                            messageLocation,
                            Collections.<PayloadTableEntry>emptyList(),
                            payloadGeneratorsUIHandlers);
            a.setVisible(true);
            a.dispose();

            payloads = a.getPayloads();
            if (payloads.isEmpty()) {
                return null;
            }
        } else {
            payloads = Collections.emptyList();
        }

        return new FuzzLocationTableEntry(messageLocation, highlight, highlightReference, payloads);
    }

    @Override
    protected Dialog getParentOwner() {
        return (Dialog) super.getParentOwner();
    }

    @Override
    public FuzzLocationTableEntry showModifyDialogue(FuzzLocationTableEntry e) {
        // Do nothing, fuzz locations can't be modified, just added and removed.
        return null;
    }

    public boolean hasLocations() {
        return !getMultipleOptionsModel().getElements().isEmpty();
    }

    public boolean hasAllLocationsWithPayloads() {
        for (FuzzLocationTableEntry entry : getMultipleOptionsModel().getElements()) {
            if (entry.getPayloads().isEmpty()) {
                return false;
            }
        }
        return true;
    }

    public List<PayloadGeneratorMessageLocation<?>> getFuzzMessageLocations() {
        List<PayloadGeneratorMessageLocation<?>> fuzzLocations = new ArrayList<>();
        for (FuzzLocationTableEntry entry : getMultipleOptionsModel().getElements()) {
            long numberOfPayloads = 0;
            List<PayloadGenerator<? extends Payload>> payloadGenerators;
            List<PayloadTableEntry> payloadTableEntries = entry.getPayloads();
            if (!payloadTableEntries.isEmpty()) {
                payloadGenerators = new ArrayList<>(payloadTableEntries.size());
                for (PayloadTableEntry payloadTableEntry : payloadTableEntries) {
                    PayloadGenerator<? extends Payload> payloadGenerator =
                            payloadTableEntry.getPayloadGeneratorUI().getPayloadGenerator();
                    List<PayloadProcessorTableEntry> processors =
                            payloadTableEntry.getPayloadProcessors();
                    numberOfPayloads += payloadGenerator.getNumberOfPayloads();
                    if (processors.isEmpty()) {
                        payloadGenerators.add(payloadGenerator);
                    } else {
                        payloadGenerators.add(
                                wrapProcessedPayloadGenerator(
                                        (PayloadGenerator) payloadGenerator, processors));
                    }
                }
            } else {
                payloadGenerators = Collections.emptyList();
            }

            List<PayloadProcessorTableEntry> processors = entry.getProcessors();
            ResettableAutoCloseableIterator<?> payloadsIterator;
            if (processors.isEmpty()) {
                payloadsIterator = new CompositePayloadGenerator(payloadGenerators).iterator();
            } else {
                payloadsIterator =
                        wrapProcessedPayloadGenerator(
                                        new CompositePayloadGenerator(payloadGenerators),
                                        processors)
                                .iterator();
            }

            fuzzLocations.add(
                    new PayloadGeneratorMessageLocation(
                            entry.getLocation(), numberOfPayloads, payloadsIterator));
        }

        return fuzzLocations;
    }

    private static <T2 extends Payload, T3 extends PayloadProcessor<T2>>
            ProcessedPayloadGenerator<T2> wrapProcessedPayloadGenerator(
                    PayloadGenerator<T2> payloadGenerator,
                    List<PayloadProcessorTableEntry> processorTableEntries) {
        List<PayloadProcessor<T2>> processors = new ArrayList<>(processorTableEntries.size());
        for (PayloadProcessorTableEntry processorTableEntry : processorTableEntries) {
            processors.add(
                    (PayloadProcessor<T2>)
                            processorTableEntry.getPayloadProcessorUI().getPayloadProcessor());
        }
        return new ProcessedPayloadGenerator<>(payloadGenerator, processors);
    }

    private static ResettableAutoCloseableIterator<Payload> getPayloads(
            FuzzLocationTableEntry locationEntry) {
        List<PayloadGenerator<? extends Payload>> payloadGenerators;
        List<PayloadTableEntry> payloadTableEntries = locationEntry.getPayloads();
        if (!payloadTableEntries.isEmpty()) {
            payloadGenerators = new ArrayList<>(payloadTableEntries.size());
            for (PayloadTableEntry payloadTableEntry : payloadTableEntries) {
                PayloadGenerator<? extends Payload> payloadGenerator =
                        payloadTableEntry.getPayloadGeneratorUI().getPayloadGenerator();
                List<PayloadProcessorTableEntry> processors =
                        payloadTableEntry.getPayloadProcessors();
                if (processors.isEmpty()) {
                    payloadGenerators.add(payloadGenerator);
                } else {
                    payloadGenerators.add(
                            new PayloadsProcessedIterator(
                                    payloadGenerator.iterator(), convert(processors)));
                }
            }
        } else {
            payloadGenerators = Collections.emptyList();
        }

        return new CompositePayloadGenerator(payloadGenerators).iterator();
    }

    private static List<PayloadProcessor<? extends Payload>> convert(
            List<PayloadProcessorTableEntry> processorTableEntries) {
        List<PayloadProcessor<? extends Payload>> processors =
                new ArrayList<>(processorTableEntries.size());
        for (PayloadProcessorTableEntry processorTableEntry : processorTableEntries) {
            processors.add(processorTableEntry.getPayloadProcessorUI().getPayloadProcessor());
        }
        return processors;
    }
}
