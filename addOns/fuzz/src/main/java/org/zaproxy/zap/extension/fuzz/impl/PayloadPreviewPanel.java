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

import java.awt.event.AdjustmentEvent;
import java.awt.event.AdjustmentListener;
import java.awt.event.ItemEvent;
import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.fuzz.payloads.Payload;
import org.zaproxy.zap.extension.fuzz.payloads.processor.PayloadProcessingException;
import org.zaproxy.zap.extension.fuzz.payloads.processor.PayloadProcessor;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.PayloadProcessorUIPanel;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.utils.ResettableAutoCloseableIterator;

class PayloadPreviewPanel {

    private static final Logger LOGGER = LogManager.getLogger(PayloadPreviewPanel.class);

    private static final String GENERATE_PREVIEW_BUTTON_LABEL =
            Constant.messages.getString("fuzz.fuzzer.processors.button.generatePreview.label");
    private static final String LOCK_SCROLL_BARS_BUTTON_LABEL =
            Constant.messages.getString("fuzz.fuzzer.processors.button.lockScroll.label");
    private static final String CURRENT_PAYLOADS_FIELD_LABEL =
            Constant.messages.getString("fuzz.fuzzer.processors.currentPayloads.label");
    private static final String PROCESSED_PAYLOADS_FIELD_LABEL =
            Constant.messages.getString("fuzz.fuzzer.processors.processedPayloads.label");

    private static final int MAX_NUMBER_PAYLOADS_PREVIEW = 50;

    private final JPanel mainPanel;
    private final ResettableAutoCloseableIterator<Payload> payloads;

    private JButton payloadsPreviewGenerateButton;

    private JTextArea currentPayloadsTextArea;
    private JTextArea processedPayloadsTextArea;

    private PayloadProcessorUIPanel<?, ?, ?> payloadProcessorUIPanel;

    public PayloadPreviewPanel(ResettableAutoCloseableIterator<Payload> payloads) {
        this.payloads = payloads;

        JLabel currentPayloadsLabel = new JLabel(CURRENT_PAYLOADS_FIELD_LABEL);
        currentPayloadsLabel.setLabelFor(getCurrentPayloadsTextArea());

        JLabel processedPayloadsLabel = new JLabel(PROCESSED_PAYLOADS_FIELD_LABEL);
        processedPayloadsLabel.setLabelFor(getProcessedPayloadsTextArea());

        JScrollPane currentPayloadsScrollPane = new JScrollPane(getCurrentPayloadsTextArea());
        JScrollPane processedPayloadsScrollPane = new JScrollPane(getProcessedPayloadsTextArea());

        SyncScrollBarsAdjustmentListener syncScrollPanes =
                new SyncScrollBarsAdjustmentListener(
                        currentPayloadsScrollPane, processedPayloadsScrollPane);

        JPanel panel =
                createSplitPanel(
                        createLabelledPanel(currentPayloadsLabel, currentPayloadsScrollPane),
                        createLabelledPanel(processedPayloadsLabel, processedPayloadsScrollPane),
                        syncScrollPanes);

        mainPanel = new JPanel();

        GroupLayout layout = new GroupLayout(mainPanel);
        mainPanel.setLayout(layout);
        layout.setAutoCreateGaps(true);

        layout.setHorizontalGroup(
                layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                        .addComponent(getPayloadsPreviewGenerateButton())
                        .addComponent(panel));
        layout.setVerticalGroup(
                layout.createSequentialGroup()
                        .addComponent(getPayloadsPreviewGenerateButton())
                        .addComponent(panel));

        updatePayloadsTextArea(
                getCurrentPayloadsTextArea(), NullPayloadProcessor.getNullPayloadProcessor());
    }

    public void setPayloadProcessorUIPanel(PayloadProcessorUIPanel<?, ?, ?> panel) {
        this.payloadProcessorUIPanel = panel;
        getPayloadsPreviewGenerateButton().setEnabled(panel != null);
    }

    public void resetPreview() {
        getProcessedPayloadsTextArea().setText("");
    }

    private JButton getPayloadsPreviewGenerateButton() {
        if (payloadsPreviewGenerateButton == null) {
            payloadsPreviewGenerateButton = new JButton(GENERATE_PREVIEW_BUTTON_LABEL);
            payloadsPreviewGenerateButton.setEnabled(false);
            payloadsPreviewGenerateButton.addActionListener(e -> updateProcessedPayloadsTextArea());
        }
        return payloadsPreviewGenerateButton;
    }

    private JTextArea getCurrentPayloadsTextArea() {
        if (currentPayloadsTextArea == null) {
            currentPayloadsTextArea = new JTextArea(20, 20);
            currentPayloadsTextArea.setEditable(false);
            currentPayloadsTextArea.setFont(FontUtils.getFont("Monospaced"));
        }
        return currentPayloadsTextArea;
    }

    private JTextArea getProcessedPayloadsTextArea() {
        if (processedPayloadsTextArea == null) {
            processedPayloadsTextArea = new JTextArea(20, 20);
            processedPayloadsTextArea.setEditable(false);
            processedPayloadsTextArea.setFont(FontUtils.getFont("Monospaced"));
        }
        return processedPayloadsTextArea;
    }

    private void updatePayloadsTextArea(JTextArea textArea, PayloadProcessor<Payload> processor) {
        if (payloads == null || processor == null) {
            return;
        }

        StringBuilder contents = new StringBuilder();
        try {
            for (int i = 0; i < MAX_NUMBER_PAYLOADS_PREVIEW && payloads.hasNext(); i++) {
                if (contents.length() > 0) {
                    contents.append('\n');
                }
                contents.append(processor.process(payloads.next().copy()).getValue());
            }
            textArea.setEnabled(true);
        } catch (Exception e) {
            LOGGER.debug("Failed to iterate the payloads: {}", e.getMessage());
            contents.setLength(0);
            contents.append(
                    Constant.messages.getString("fuzz.fuzzer.processors.payloadsPreview.error"));
            textArea.setEnabled(false);
        } finally {
            try {
                payloads.reset();
            } catch (Exception e) {
                LOGGER.debug("Failed to close iterator: {}", e.getMessage());
            }
        }
        textArea.setText(contents.toString());
        textArea.setCaretPosition(0);
    }

    private void updateProcessedPayloadsTextArea() {
        updatePayloadsTextArea(
                getProcessedPayloadsTextArea(),
                (PayloadProcessor<Payload>) payloadProcessorUIPanel.getPayloadProcessor());
    }

    public JPanel getPanel() {
        return mainPanel;
    }

    public void clear() {
        getCurrentPayloadsTextArea().setText("");
        getProcessedPayloadsTextArea().setText("");
    }

    private static class NullPayloadProcessor<T extends Payload> implements PayloadProcessor<T> {

        private static final NullPayloadProcessor<?> NULL_PAYLOAD_PROCESSOR =
                new NullPayloadProcessor<>();

        @Override
        public T process(T payload) throws PayloadProcessingException {
            return payload;
        }

        @Override
        public PayloadProcessor<T> copy() {
            return this;
        }

        @SuppressWarnings("unchecked")
        public static <T extends Payload> NullPayloadProcessor<T> getNullPayloadProcessor() {
            return (NullPayloadProcessor<T>) NullPayloadProcessor.NULL_PAYLOAD_PROCESSOR;
        }
    }

    private static JPanel createSplitPanel(
            JPanel leftPanel,
            JPanel rightPanel,
            final SyncScrollBarsAdjustmentListener syncScrollPanes) {
        JPanel panel = new JPanel();

        GroupLayout layout = new GroupLayout(panel);
        panel.setLayout(layout);
        layout.setAutoCreateGaps(true);

        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, rightPanel);
        splitPane.setDividerLocation(0.5D);
        splitPane.setResizeWeight(0.5D);

        JCheckBox syncScrollBarsCheckbox = new JCheckBox(LOCK_SCROLL_BARS_BUTTON_LABEL);
        syncScrollBarsCheckbox.setSelected(true);
        syncScrollBarsCheckbox.addItemListener(
                e -> syncScrollPanes.setSync(e.getStateChange() == ItemEvent.SELECTED));

        layout.setHorizontalGroup(
                layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                        .addComponent(splitPane)
                        .addComponent(syncScrollBarsCheckbox));
        layout.setVerticalGroup(
                layout.createSequentialGroup()
                        .addComponent(splitPane)
                        .addComponent(syncScrollBarsCheckbox));

        return panel;
    }

    private static JPanel createLabelledPanel(JLabel label, JComponent component) {
        JPanel panel = new JPanel();

        GroupLayout layout = new GroupLayout(panel);
        panel.setLayout(layout);
        layout.setAutoCreateGaps(true);

        layout.setHorizontalGroup(
                layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                        .addComponent(label)
                        .addComponent(component));
        layout.setVerticalGroup(
                layout.createSequentialGroup().addComponent(label).addComponent(component));

        return panel;
    }

    private static class SyncScrollBarsAdjustmentListener implements AdjustmentListener {

        private final JScrollPane scrollPaneA;
        private final JScrollPane scrollPaneB;
        private boolean sync;

        public SyncScrollBarsAdjustmentListener(JScrollPane scrollPaneA, JScrollPane scrollPaneB) {
            this.scrollPaneA = scrollPaneA;
            scrollPaneA.getHorizontalScrollBar().addAdjustmentListener(this);
            scrollPaneA.getVerticalScrollBar().addAdjustmentListener(this);
            this.scrollPaneB = scrollPaneB;
            scrollPaneB.getHorizontalScrollBar().addAdjustmentListener(this);
            scrollPaneB.getVerticalScrollBar().addAdjustmentListener(this);
            this.sync = true;
        }

        @Override
        public void adjustmentValueChanged(AdjustmentEvent e) {
            if (sync) {
                if (scrollPaneA.getVerticalScrollBar().equals(e.getSource())) {
                    scrollPaneB
                            .getVerticalScrollBar()
                            .setValue(scrollPaneA.getVerticalScrollBar().getValue());
                } else if (scrollPaneB.getVerticalScrollBar().equals(e.getSource())) {
                    scrollPaneA
                            .getVerticalScrollBar()
                            .setValue(scrollPaneB.getVerticalScrollBar().getValue());
                } else if (scrollPaneA.getHorizontalScrollBar().equals(e.getSource())) {
                    scrollPaneB
                            .getHorizontalScrollBar()
                            .setValue(scrollPaneA.getHorizontalScrollBar().getValue());
                } else if (scrollPaneB.getHorizontalScrollBar().equals(e.getSource())) {
                    scrollPaneA
                            .getHorizontalScrollBar()
                            .setValue(scrollPaneB.getHorizontalScrollBar().getValue());
                }
            }
        }

        public void setSync(boolean sync) {
            this.sync = sync;
        }
    }
}
