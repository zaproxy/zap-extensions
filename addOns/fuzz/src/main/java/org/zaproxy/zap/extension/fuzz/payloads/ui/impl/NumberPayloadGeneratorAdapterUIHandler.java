/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.zap.extension.fuzz.payloads.ui.impl;

import java.text.MessageFormat;
import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;
import org.zaproxy.zap.extension.fuzz.payloads.generator.NumberPayloadGenerator;
import org.zaproxy.zap.extension.fuzz.payloads.generator.PayloadGenerator;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUI;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUIHandler;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUIPanel;
import org.zaproxy.zap.model.MessageLocation;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.utils.ResettableAutoCloseableIterator;
import org.zaproxy.zap.utils.ZapNumberSpinner;

public class NumberPayloadGeneratorAdapterUIHandler
        implements PayloadGeneratorUIHandler<
                DefaultPayload,
                NumberPayloadGenerator,
                NumberPayloadGeneratorAdapterUIHandler.NumberPayloadGeneratorUI> {

    private static final Logger LOGGER =
            LogManager.getLogger(NumberPayloadGeneratorAdapterUIHandler.class);
    private static final String PAYLOAD_GENERATOR_NAME =
            Constant.messages.getString("fuzz.payloads.generator.numbers.name");
    private static final String PAYLOAD_GENERATOR_DESC =
            Constant.messages.getString("fuzz.payloads.generator.numbers.description");
    private static final int DEFAULT_STEP = 1;

    @Override
    public String getName() {
        return PAYLOAD_GENERATOR_NAME;
    }

    @Override
    public Class<NumberPayloadGeneratorAdapterUIHandler.NumberPayloadGeneratorUI>
            getPayloadGeneratorUIClass() {
        return NumberPayloadGeneratorUI.class;
    }

    @Override
    public Class<NumberPayloadGeneratorAdapterUIHandler.NumberPayloadGeneratorUIPanel>
            getPayloadGeneratorUIPanelClass() {
        return NumberPayloadGeneratorUIPanel.class;
    }

    @Override
    public PayloadGeneratorUIPanel<
                    DefaultPayload,
                    NumberPayloadGenerator,
                    NumberPayloadGeneratorAdapterUIHandler.NumberPayloadGeneratorUI>
            createPanel() {
        return new NumberPayloadGeneratorUIPanel();
    }

    public static class NumberPayloadGeneratorUI
            implements PayloadGeneratorUI<DefaultPayload, NumberPayloadGenerator> {

        private final NumberPayloadGenerator numberPayloadGenerator;

        public NumberPayloadGeneratorUI(NumberPayloadGenerator generator) {
            this.numberPayloadGenerator = generator;
        }

        @Override
        public Class<? extends NumberPayloadGenerator> getPayloadGeneratorClass() {
            return NumberPayloadGenerator.class;
        }

        @Override
        public String getName() {
            return PAYLOAD_GENERATOR_NAME;
        }

        @Override
        public String getDescription() {
            return MessageFormat.format(
                    PAYLOAD_GENERATOR_DESC,
                    numberPayloadGenerator.getFrom(),
                    numberPayloadGenerator.getTo(),
                    numberPayloadGenerator.getStep());
        }

        @Override
        public long getNumberOfPayloads() {
            try {
                return numberPayloadGenerator.getNumberOfPayloads();
            } catch (Exception e) {
                LOGGER.warn("Failed to obtain number of payloads", e);
            }
            return PayloadGenerator.UNKNOWN_NUMBER_OF_PAYLOADS;
        }

        @Override
        public NumberPayloadGenerator getPayloadGenerator() {
            return numberPayloadGenerator;
        }

        @Override
        public PayloadGeneratorUI<DefaultPayload, NumberPayloadGenerator> copy() {
            return this;
        }
    }

    public static class NumberPayloadGeneratorUIPanel
            extends AbstractPersistentPayloadGeneratorUIPanel<
                    DefaultPayload, NumberPayloadGenerator, NumberPayloadGeneratorUI> {

        private static final String PAYLOADS_PREVIEW_FIELD_LABEL =
                Constant.messages.getString(
                        "fuzz.payloads.generator.numbers.payloadsPreview.label");
        private static final String PAYLOADS_PREVIEW_GENERATE_FIELD_LABEL =
                Constant.messages.getString(
                        "fuzz.payloads.generator.numbers.payloadsPreviewGenerate.label");
        private static final String PAYLOADS_FROM_LABEL =
                Constant.messages.getString("fuzz.payloads.generator.numbers.from.label");
        private static final String PAYLOADS_TO_LABEL =
                Constant.messages.getString("fuzz.payloads.generator.numbers.to.label");
        private static final String PAYLOADS_INCREMENT_LABEL =
                Constant.messages.getString("fuzz.payloads.generator.numbers.increment.label");

        private static final int MAX_NUMBER_PAYLOADS_PREVIEW = 250;

        private JPanel fieldsPanel;
        private JTextArea payloadsPreviewTextArea;
        private JButton payloadsPreviewGenerateButton;
        private ZapNumberSpinner fromField;
        private ZapNumberSpinner toField;
        private ZapNumberSpinner stepField;

        private NumberPayloadGeneratorUI oldGenerator;

        public NumberPayloadGeneratorUIPanel() {

            fieldsPanel = new JPanel();

            GroupLayout layout = new GroupLayout(fieldsPanel);
            fieldsPanel.setLayout(layout);
            layout.setAutoCreateGaps(true);

            fromField = new ZapNumberSpinner(Integer.MIN_VALUE, 0, Integer.MAX_VALUE);
            toField = new ZapNumberSpinner(Integer.MIN_VALUE, 0, Integer.MAX_VALUE);
            stepField = new ZapNumberSpinner(Integer.MIN_VALUE, DEFAULT_STEP, Integer.MAX_VALUE);

            JLabel fromLabel = new JLabel(PAYLOADS_FROM_LABEL);
            fromLabel.setLabelFor(fromField);

            JLabel toLabel = new JLabel(PAYLOADS_TO_LABEL);
            toLabel.setLabelFor(toField);

            JLabel stepLabel = new JLabel(PAYLOADS_INCREMENT_LABEL);
            stepLabel.setLabelFor(stepField);

            JLabel payloadsPreviewLabel = new JLabel(PAYLOADS_PREVIEW_FIELD_LABEL);
            payloadsPreviewLabel.setLabelFor(getPayloadsPreviewTextArea());
            JScrollPane payloadsPreviewScrollPane = new JScrollPane(getPayloadsPreviewTextArea());

            setPreviewAndSaveButtonsEnabled(true);
            layout.setHorizontalGroup(
                    layout.createSequentialGroup()
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                            .addComponent(fromLabel)
                                            .addComponent(toLabel)
                                            .addComponent(stepLabel)
                                            .addComponent(payloadsPreviewLabel))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                            .addComponent(fromField)
                                            .addComponent(toField)
                                            .addComponent(stepField)
                                            .addGroup(
                                                    layout.createSequentialGroup()
                                                            .addComponent(
                                                                    getPayloadsPreviewGenerateButton())
                                                            .addComponent(getSaveButton()))
                                            .addComponent(payloadsPreviewScrollPane)));
            layout.setVerticalGroup(
                    layout.createSequentialGroup()
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(fromLabel)
                                            .addComponent(fromField))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(toLabel)
                                            .addComponent(toField))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(stepLabel)
                                            .addComponent(stepField))
                            .addGroup(
                                    layout.createParallelGroup()
                                            .addComponent(getPayloadsPreviewGenerateButton())
                                            .addComponent(getSaveButton()))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(payloadsPreviewLabel)
                                            .addComponent(payloadsPreviewScrollPane)));
        }

        @Override
        protected NumberPayloadGenerator getPayloadGenerator() {
            if (!validate()) {
                return null;
            }
            int f = fromField.getValue();
            int t = toField.getValue();
            int s = stepField.getValue();
            return new NumberPayloadGenerator(f, t, s);
        }

        @Override
        public void init(MessageLocation messageLocation) {}

        @Override
        public JPanel getComponent() {
            return fieldsPanel;
        }

        @Override
        public void setPayloadGeneratorUI(NumberPayloadGeneratorUI payloadGeneratorUI) {
            oldGenerator = payloadGeneratorUI;
            fromField.setValue(payloadGeneratorUI.getPayloadGenerator().getFrom());
            toField.setValue(payloadGeneratorUI.getPayloadGenerator().getTo());
            stepField.setValue(payloadGeneratorUI.getPayloadGenerator().getStep());
        }

        @Override
        public NumberPayloadGeneratorUI getPayloadGeneratorUI() {
            if (oldGenerator != null) {
                return oldGenerator;
            }

            return new NumberPayloadGeneratorUI(getPayloadGenerator());
        }

        @Override
        public void clear() {
            oldGenerator = null;
            getPayloadsPreviewTextArea().setText("");
            fromField.setValue(0);
            toField.setValue(0);
            stepField.setValue(DEFAULT_STEP);
        }

        @Override
        public boolean validate() {
            if (oldGenerator != null
                    && fromField.getValue() == oldGenerator.getPayloadGenerator().getFrom()
                    && toField.getValue() == oldGenerator.getPayloadGenerator().getTo()
                    && stepField.getValue() == oldGenerator.getPayloadGenerator().getStep()) {
                return true;
            }

            if (stepField.getValue() == 0) return false;
            if ((fromField.getValue() > toField.getValue()) && stepField.getValue() > 0)
                return false;

            oldGenerator = null;
            return true;
        }

        private void setPreviewAndSaveButtonsEnabled(boolean enabled) {
            getPayloadsPreviewGenerateButton().setEnabled(enabled);
            getSaveButton().setEnabled(enabled);
        }

        private JButton getPayloadsPreviewGenerateButton() {
            if (payloadsPreviewGenerateButton == null) {
                payloadsPreviewGenerateButton = new JButton(PAYLOADS_PREVIEW_GENERATE_FIELD_LABEL);
                payloadsPreviewGenerateButton.setEnabled(false);

                payloadsPreviewGenerateButton.addActionListener(
                        e -> updatePayloadsPreviewTextArea());
            }
            return payloadsPreviewGenerateButton;
        }

        private JTextArea getPayloadsPreviewTextArea() {
            if (payloadsPreviewTextArea == null) {
                payloadsPreviewTextArea = new JTextArea(15, 10);
                payloadsPreviewTextArea.setEditable(false);
                payloadsPreviewTextArea.setFont(FontUtils.getFont("Monospaced"));
            }
            return payloadsPreviewTextArea;
        }

        private void updatePayloadsPreviewTextArea() {
            NumberPayloadGenerator payloadGenerator = getPayloadGenerator();
            if (payloadGenerator == null) {
                return;
            }
            StringBuilder contents = new StringBuilder();
            try (ResettableAutoCloseableIterator<DefaultPayload> payloads =
                    payloadGenerator.iterator()) {

                for (int i = 0; i < MAX_NUMBER_PAYLOADS_PREVIEW && payloads.hasNext(); i++) {
                    if (contents.length() > 0) {
                        contents.append('\n');
                    }
                    contents.append(payloads.next().getValue());
                }
            }
            getPayloadsPreviewTextArea().setEnabled(true);
            getPayloadsPreviewTextArea().setText(contents.toString());
            getPayloadsPreviewTextArea().setCaretPosition(0);
        }
    }
}
