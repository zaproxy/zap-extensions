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
package org.zaproxy.zap.extension.fuzz.payloads.ui.impl;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.text.MessageFormat;

import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.fuzz.payloads.StringPayload;
import org.zaproxy.zap.extension.fuzz.payloads.generator.RegexPayloadGenerator;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUI;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUIHandler;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUIPanel;
import org.zaproxy.zap.extension.fuzz.payloads.ui.impl.RegexPayloadGeneratorUIHandler.RegexPayloadGeneratorUI;
import org.zaproxy.zap.model.MessageLocation;
import org.zaproxy.zap.utils.ResettableAutoCloseableIterator;
import org.zaproxy.zap.utils.ZapNumberSpinner;
import org.zaproxy.zap.utils.ZapTextField;

public class RegexPayloadGeneratorUIHandler implements
        PayloadGeneratorUIHandler<String, StringPayload, RegexPayloadGenerator, RegexPayloadGeneratorUI> {

    private static final String PAYLOAD_GENERATOR_NAME = Constant.messages.getString("fuzz.payloads.generator.regex.name");

    @Override
    public String getName() {
        return PAYLOAD_GENERATOR_NAME;
    }

    @Override
    public Class<RegexPayloadGeneratorUI> getPayloadGeneratorUIClass() {
        return RegexPayloadGeneratorUI.class;
    }

    @Override
    public Class<RegexPayloadGeneratorUIPanel> getPayloadGeneratorUIPanelClass() {
        return RegexPayloadGeneratorUIPanel.class;
    }

    @Override
    public RegexPayloadGeneratorUIPanel createPanel() {
        return new RegexPayloadGeneratorUIPanel();
    }

    public static class RegexPayloadGeneratorUI implements PayloadGeneratorUI<String, StringPayload, RegexPayloadGenerator> {

        private final String regex;
        private final int maxPayloads;
        private final int maxPayloadLength;

        public RegexPayloadGeneratorUI(String regex, int maxPayloads, int maxPayloadLength) {
            this.regex = regex;
            this.maxPayloads = maxPayloads;
            this.maxPayloadLength = maxPayloadLength;
        }

        public String getRegex() {
            return regex;
        }

        public int getMaxPayloads() {
            return maxPayloads;
        }

        public int getMaxPayloadLength() {
            return maxPayloadLength;
        }

        @Override
        public Class<RegexPayloadGenerator> getPayloadGeneratorClass() {
            return RegexPayloadGenerator.class;
        }

        @Override
        public String getName() {
            return PAYLOAD_GENERATOR_NAME;
        }

        @Override
        public String getDescription() {
            StringBuilder descriptionBuilder = new StringBuilder(150);
            String lengthDescription = (maxPayloadLength != 0) ? MessageFormat.format(
                    Constant.messages.getString("fuzz.payloads.generator.regex.description.length"),
                    Integer.valueOf(maxPayloadLength)) : "";

            String message = MessageFormat.format(
                    Constant.messages.getString("fuzz.payloads.generator.regex.description.base"),
                    regex,
                    Integer.valueOf(maxPayloads),
                    lengthDescription);

            descriptionBuilder.append(message);

            return descriptionBuilder.toString();
        }

        @Override
        public long getNumberOfPayloads() {
            return RegexPayloadGenerator.calculateNumberOfPayloads(regex, maxPayloads, maxPayloadLength);
        }

        @Override
        public RegexPayloadGenerator getPayloadGenerator() {
            return new RegexPayloadGenerator(regex, maxPayloads, maxPayloadLength);
        }

        @Override
        public RegexPayloadGeneratorUI copy() {
            return this;
        }

    }

    public static class RegexPayloadGeneratorUIPanel implements
            PayloadGeneratorUIPanel<String, StringPayload, RegexPayloadGenerator, RegexPayloadGeneratorUI> {

        private static final int DEFAULT_MAX_PAYLOADS = 1000;
        private static final int DEFAULT_MAX_LENGTH = 0;

        private static final int MAX_NUMBER_PAYLOADS_PREVIEW = 250;

        private static final String CONTENTS_FIELD_LABEL = Constant.messages.getString("fuzz.payloads.generator.regex.regex.label");
        private static final String MAX_PAYLOADS_FIELD_LABEL = Constant.messages.getString("fuzz.payloads.generator.regex.maxPayloads.label");
        private static final String MAX_PAYLOADS_FIELD_TOOL_TIP = Constant.messages.getString("fuzz.payloads.generator.regex.maxPayloads.tooltip");
        private static final String MAX_LENGTH_FIELD_LABEL = Constant.messages.getString("fuzz.payloads.generator.regex.maxLength");
        private static final String MAX_LENGTH_FIELD_TOOL_TIP = Constant.messages.getString("fuzz.payloads.generator.regex.maxLength.tooltip");

        private static final String PAYLOADS_PREVIEW_FIELD_LABEL = Constant.messages.getString("fuzz.payloads.generator.regex.payloadsPreview.label");
        private static final String PAYLOADS_PREVIEW_GENERATE_FIELD_LABEL = Constant.messages.getString("fuzz.payloads.generator.regex.payloadsPreviewGenerate.label");

        private JPanel fieldsPanel;

        private ZapTextField regexTextField;
        private ZapNumberSpinner maxPayloadsNumberSpinner;
        private ZapNumberSpinner maxLengthNumberSpinner;

        private JTextArea payloadsPreviewTextArea;
        private JButton payloadsPreviewGenerateButton;

        public RegexPayloadGeneratorUIPanel() {
            fieldsPanel = new JPanel();

            GroupLayout layout = new GroupLayout(fieldsPanel);
            fieldsPanel.setLayout(layout);
            layout.setAutoCreateGaps(true);

            JLabel regexLabel = new JLabel(CONTENTS_FIELD_LABEL);
            regexLabel.setLabelFor(getRegexTextField());
            JLabel multilineLabel = new JLabel(MAX_PAYLOADS_FIELD_LABEL);
            multilineLabel.setLabelFor(getMaxPayloadsNumberSpinner());
            multilineLabel.setToolTipText(MAX_PAYLOADS_FIELD_TOOL_TIP);
            JLabel maxLengthLabel = new JLabel(MAX_LENGTH_FIELD_LABEL);
            maxLengthLabel.setLabelFor(getMaxLengthNumberSpinner());
            maxLengthLabel.setToolTipText(MAX_LENGTH_FIELD_TOOL_TIP);
            JLabel payloadsPreviewLabel = new JLabel(PAYLOADS_PREVIEW_FIELD_LABEL);
            payloadsPreviewLabel.setLabelFor(getPayloadsPreviewTextArea());

            JScrollPane payloadsPreviewScrollPane = new JScrollPane(getPayloadsPreviewTextArea());

            layout.setHorizontalGroup(layout.createSequentialGroup()
                    .addGroup(
                            layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                    .addComponent(regexLabel)
                                    .addComponent(multilineLabel)
                                    .addComponent(maxLengthLabel)
                                    .addComponent(payloadsPreviewLabel))
                    .addGroup(
                            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                    .addComponent(getRegexTextField())
                                    .addComponent(getMaxPayloadsNumberSpinner())
                                    .addComponent(getMaxLengthNumberSpinner())
                                    .addComponent(getPayloadsPreviewGenerateButton())
                                    .addComponent(payloadsPreviewScrollPane)));

            layout.setVerticalGroup(layout.createSequentialGroup()
                    .addGroup(
                            layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                    .addComponent(regexLabel)
                                    .addComponent(getRegexTextField()))
                    .addGroup(
                            layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                    .addComponent(multilineLabel)
                                    .addComponent(getMaxPayloadsNumberSpinner()))
                    .addGroup(
                            layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                    .addComponent(maxLengthLabel)
                                    .addComponent(getMaxLengthNumberSpinner()))
                    .addComponent(getPayloadsPreviewGenerateButton())
                    .addGroup(
                            layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                    .addComponent(payloadsPreviewLabel)
                                    .addComponent(payloadsPreviewScrollPane)));
        }

        private ZapTextField getRegexTextField() {
            if (regexTextField == null) {
                regexTextField = new ZapTextField();
                regexTextField.setColumns(25);
                regexTextField.getDocument().addDocumentListener(new DocumentListener() {

                    @Override
                    public void removeUpdate(DocumentEvent e) {
                        update();
                    }

                    @Override
                    public void insertUpdate(DocumentEvent e) {
                        update();
                    }

                    @Override
                    public void changedUpdate(DocumentEvent e) {
                        update();
                    }

                    private void update() {
                        getPayloadsPreviewGenerateButton().setEnabled(!regexTextField.getText().isEmpty());
                    }
                });
            }
            return regexTextField;
        }

        private ZapNumberSpinner getMaxPayloadsNumberSpinner() {
            if (maxPayloadsNumberSpinner == null) {
                maxPayloadsNumberSpinner = new ZapNumberSpinner(1, DEFAULT_MAX_PAYLOADS, Integer.MAX_VALUE);
                maxPayloadsNumberSpinner.setToolTipText(MAX_PAYLOADS_FIELD_TOOL_TIP);
            }
            return maxPayloadsNumberSpinner;
        }

        private ZapNumberSpinner getMaxLengthNumberSpinner() {
            if (maxLengthNumberSpinner == null) {
                maxLengthNumberSpinner = new ZapNumberSpinner(0, DEFAULT_MAX_LENGTH, Integer.MAX_VALUE);
                maxLengthNumberSpinner.setToolTipText(MAX_LENGTH_FIELD_TOOL_TIP);
            }
            return maxLengthNumberSpinner;
        }

        private JButton getPayloadsPreviewGenerateButton() {
            if (payloadsPreviewGenerateButton == null) {
                payloadsPreviewGenerateButton = new JButton(PAYLOADS_PREVIEW_GENERATE_FIELD_LABEL);
                payloadsPreviewGenerateButton.setEnabled(false);

                payloadsPreviewGenerateButton.addActionListener(new ActionListener() {

                    @Override
                    public void actionPerformed(ActionEvent e) {
                        updatePayloadsPreviewTextArea();
                    }
                });
            }
            return payloadsPreviewGenerateButton;
        }

        private JTextArea getPayloadsPreviewTextArea() {
            if (payloadsPreviewTextArea == null) {
                payloadsPreviewTextArea = new JTextArea(15, 10);
                payloadsPreviewTextArea.setEditable(false);
            }
            return payloadsPreviewTextArea;
        }

        private void updatePayloadsPreviewTextArea() {
            StringBuilder contents = new StringBuilder();
            try {
                try (ResettableAutoCloseableIterator<StringPayload> payloads = new RegexPayloadGenerator(
                        getRegexTextField().getText(),
                        MAX_NUMBER_PAYLOADS_PREVIEW,
                        getMaxLengthNumberSpinner().getValue().intValue()).iterator()) {
                    for (int i = 0; i < MAX_NUMBER_PAYLOADS_PREVIEW && payloads.hasNext(); i++) {
                        if (contents.length() > 0) {
                            contents.append('\n');
                        }
                        contents.append(payloads.next().getValue());
                    }
                }
                getPayloadsPreviewTextArea().setEnabled(true);
            } catch (Exception ignore) {
                contents.setLength(0);
                contents.append(Constant.messages.getString("fuzz.payloads.generator.regex.payloadsPreview.error"));
                getPayloadsPreviewTextArea().setEnabled(false);
            }
            getPayloadsPreviewTextArea().setText(contents.toString());
            getPayloadsPreviewTextArea().setCaretPosition(0);
        }

        @Override
        public void init(MessageLocation messageLocation) {
        }

        @Override
        public JPanel getComponent() {
            return fieldsPanel;
        }

        @Override
        public void setPayloadGeneratorUI(RegexPayloadGeneratorUI payloadGeneratorUI) {
            getRegexTextField().setText(payloadGeneratorUI.getRegex());
            getMaxPayloadsNumberSpinner().setValue(payloadGeneratorUI.getMaxPayloads());
            getMaxLengthNumberSpinner().setValue(payloadGeneratorUI.getMaxPayloadLength());
            getPayloadsPreviewGenerateButton().setEnabled(true);
        }

        @Override
        public RegexPayloadGeneratorUI getPayloadGeneratorUI() {
            return new RegexPayloadGeneratorUI(getRegexTextField().getText(), getMaxPayloadsNumberSpinner().getValue()
                    .intValue(), getMaxLengthNumberSpinner().getValue().intValue());
        }

        @Override
        public void clear() {
            getRegexTextField().setText("");
            getRegexTextField().discardAllEdits();
            getMaxPayloadsNumberSpinner().setValue(DEFAULT_MAX_PAYLOADS);
            getMaxLengthNumberSpinner().setValue(DEFAULT_MAX_LENGTH);
            getPayloadsPreviewTextArea().setText("");
        }

        @Override
        public boolean validate() {
            if (getRegexTextField().getText().isEmpty()) {
                JOptionPane.showMessageDialog(
                        null,
                        Constant.messages.getString("fuzz.payloads.generator.regex.warnNoRegex.message"),
                        Constant.messages.getString("fuzz.payloads.generator.regex.warnNoRegex.title"),
                        JOptionPane.INFORMATION_MESSAGE);
                getRegexTextField().requestFocusInWindow();
                return false;
            }
            if (RegexPayloadGenerator.calculateNumberOfPayloads(
                    getRegexTextField().getText(),
                    getMaxPayloadsNumberSpinner().getValue().intValue(),
                    getMaxLengthNumberSpinner().getValue().intValue()) == -1) {
                JOptionPane.showMessageDialog(
                        null,
                        Constant.messages.getString("fuzz.payloads.generator.regex.warnUnsupportedRegex.message"),
                        Constant.messages.getString("fuzz.payloads.generator.regex.warnUnsupportedRegex.title"),
                        JOptionPane.INFORMATION_MESSAGE);
                getRegexTextField().requestFocusInWindow();
                return false;
            }
            return true;
        }

        @Override
        public String getHelpTarget() {
            // THC add help page...
            return null;
        }
    }
}
