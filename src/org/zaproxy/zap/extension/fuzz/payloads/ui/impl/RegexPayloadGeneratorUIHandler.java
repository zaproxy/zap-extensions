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
        private final RegexPayloadGenerator payloadGenerator;

        public RegexPayloadGeneratorUI(String regex, int maxPayloads) {
            this.regex = regex;
            this.maxPayloads = maxPayloads;
            this.payloadGenerator = new RegexPayloadGenerator(
                    regex,
                    maxPayloads,
                    getMaximumForPayloadCalculation(maxPayloads));
        }

        public String getRegex() {
            return regex;
        }

        public int getMaxPayloads() {
            return maxPayloads;
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
            String maxPayloadsDescription = (maxPayloads != 0) ? MessageFormat.format(
                    Constant.messages.getString("fuzz.payloads.generator.regex.description.maxPayloads"),
                    Integer.valueOf(maxPayloads)) : "";

            String message = MessageFormat.format(
                    Constant.messages.getString("fuzz.payloads.generator.regex.description.base"),
                    regex,
                    maxPayloadsDescription);

            descriptionBuilder.append(message);

            return descriptionBuilder.toString();
        }

        @Override
        public long getNumberOfPayloads() {
            return payloadGenerator.getNumberOfPayloads();
        }

        @Override
        public RegexPayloadGenerator getPayloadGenerator() {
            return payloadGenerator;
        }

        @Override
        public RegexPayloadGeneratorUI copy() {
            return this;
        }

    }

    public static class RegexPayloadGeneratorUIPanel extends
            AbstractPersistentPayloadGeneratorUIPanel<String, StringPayload, RegexPayloadGenerator, RegexPayloadGeneratorUI> {

        private static final int DEFAULT_MAX_PAYLOADS = 1000;

        private static final int MAX_NUMBER_PAYLOADS_PERSISTENCE = 10000;

        private static final int MAX_NUMBER_PAYLOADS_PREVIEW = 250;

        private static final String CONTENTS_FIELD_LABEL = Constant.messages.getString("fuzz.payloads.generator.regex.regex.label");
        private static final String MAX_PAYLOADS_FIELD_LABEL = Constant.messages.getString("fuzz.payloads.generator.regex.maxPayloads.label");
        private static final String MAX_PAYLOADS_FIELD_TOOL_TIP = Constant.messages.getString("fuzz.payloads.generator.regex.maxPayloads.tooltip");

        private static final String PAYLOADS_PREVIEW_FIELD_LABEL = Constant.messages.getString("fuzz.payloads.generator.regex.payloadsPreview.label");
        private static final String PAYLOADS_PREVIEW_GENERATE_FIELD_LABEL = Constant.messages.getString("fuzz.payloads.generator.regex.payloadsPreviewGenerate.label");

        private JPanel fieldsPanel;

        private ZapTextField regexTextField;
        private ZapNumberSpinner maxPayloadsNumberSpinner;

        private JTextArea payloadsPreviewTextArea;
        private JButton payloadsPreviewGenerateButton;

        private RegexPayloadGeneratorUI oldGenerator;

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
            JLabel payloadsPreviewLabel = new JLabel(PAYLOADS_PREVIEW_FIELD_LABEL);
            payloadsPreviewLabel.setLabelFor(getPayloadsPreviewTextArea());

            JScrollPane payloadsPreviewScrollPane = new JScrollPane(getPayloadsPreviewTextArea());

            layout.setHorizontalGroup(layout.createSequentialGroup()
                    .addGroup(
                            layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                    .addComponent(regexLabel)
                                    .addComponent(multilineLabel)
                                    .addComponent(payloadsPreviewLabel))
                    .addGroup(
                            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                    .addComponent(getRegexTextField())
                                    .addComponent(getMaxPayloadsNumberSpinner())
                                    .addGroup(
                                            layout.createSequentialGroup()
                                                    .addComponent(getPayloadsPreviewGenerateButton())
                                                    .addComponent(getSaveButton()))
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
                            layout.createParallelGroup()
                                    .addComponent(getPayloadsPreviewGenerateButton())
                                    .addComponent(getSaveButton()))
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
                        setPreviewAndSaveButtonsEnabled(!regexTextField.getText().isEmpty());
                    }
                });
            }
            return regexTextField;
        }

        private void setPreviewAndSaveButtonsEnabled(boolean enabled) {
            getPayloadsPreviewGenerateButton().setEnabled(enabled);
            getSaveButton().setEnabled(enabled);
        }

        private ZapNumberSpinner getMaxPayloadsNumberSpinner() {
            if (maxPayloadsNumberSpinner == null) {
                maxPayloadsNumberSpinner = new ZapNumberSpinner(0, DEFAULT_MAX_PAYLOADS, Integer.MAX_VALUE);
                maxPayloadsNumberSpinner.setToolTipText(MAX_PAYLOADS_FIELD_TOOL_TIP);
            }
            return maxPayloadsNumberSpinner;
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
            RegexPayloadGenerator payloadGenerator = getPayloadGenerator();
            if (payloadGenerator == null) {
                return;
            }
            StringBuilder contents = new StringBuilder();
            try {
                try (ResettableAutoCloseableIterator<StringPayload> payloads = payloadGenerator.iterator()) {
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
            oldGenerator = payloadGeneratorUI;
            getRegexTextField().setText(payloadGeneratorUI.getRegex());
            getMaxPayloadsNumberSpinner().setValue(payloadGeneratorUI.getMaxPayloads());
            setPreviewAndSaveButtonsEnabled(true);
        }

        @Override
        public RegexPayloadGeneratorUI getPayloadGeneratorUI() {
            if (oldGenerator != null) {
                return oldGenerator;
            }
            return new RegexPayloadGeneratorUI(
                    getRegexTextField().getText(),
                    getMaxPayloadsNumberSpinner().getValue().intValue());
        }

        @Override
        protected RegexPayloadGenerator getPayloadGenerator() {
            if (!validate()) {
                return null;
            }
            return new RegexPayloadGenerator(
                    getRegexTextField().getText(),
                    getMaximumForPayloadPersistence(getMaxPayloadsNumberSpinner().getValue().intValue()));
        }

        @Override
        public void clear() {
            oldGenerator = null;
            getRegexTextField().setText("");
            getRegexTextField().discardAllEdits();
            getMaxPayloadsNumberSpinner().setValue(DEFAULT_MAX_PAYLOADS);
            getPayloadsPreviewTextArea().setText("");
        }

        @Override
        public boolean validate() {
            if (oldGenerator != null) {
                if (oldGenerator.getRegex().equals(getRegexTextField().getText())
                        && oldGenerator.getMaxPayloads() == getMaxPayloadsNumberSpinner().getValue().intValue()) {
                    return true;
                }
            }

            String regex = getRegexTextField().getText();
            if (regex.isEmpty()) {
                JOptionPane.showMessageDialog(
                        null,
                        Constant.messages.getString("fuzz.payloads.generator.regex.warnNoRegex.message"),
                        Constant.messages.getString("fuzz.payloads.generator.regex.warnNoRegex.title"),
                        JOptionPane.INFORMATION_MESSAGE);
                getRegexTextField().requestFocusInWindow();
                return false;
            }
            if (!RegexPayloadGenerator.hasValidSyntax(regex)) {
                JOptionPane.showMessageDialog(
                        null,
                        Constant.messages.getString("fuzz.payloads.generator.regex.warnInvalidRegex.message"),
                        Constant.messages.getString("fuzz.payloads.generator.regex.warnInvalidRegex.title"),
                        JOptionPane.INFORMATION_MESSAGE);
                getRegexTextField().requestFocusInWindow();
                return false;
            }
            if (!RegexPayloadGenerator.isValid(regex)) {
                JOptionPane.showMessageDialog(
                        null,
                        Constant.messages.getString("fuzz.payloads.generator.regex.warnInvalidRegexTimeCost.message"),
                        Constant.messages.getString("fuzz.payloads.generator.regex.warnInvalidRegexTimeCost.title"),
                        JOptionPane.INFORMATION_MESSAGE);
                getRegexTextField().requestFocusInWindow();
                return false;
            }
            if (getMaxPayloadsNumberSpinner().getValue().intValue() == 0 && RegexPayloadGenerator.isInfinite(regex, 0)) {
                if (JOptionPane.showConfirmDialog(
                        null,
                        Constant.messages.getString("fuzz.payloads.generator.regex.warnInfiniteRegex.message"),
                        Constant.messages.getString("fuzz.payloads.generator.regex.warnInfiniteRegex.title"),
                        JOptionPane.YES_NO_OPTION) != JOptionPane.YES_OPTION) {
                    getMaxPayloadsNumberSpinner().requestFocusInWindow();
                    return false;
                }
            } else if (calculateNumberOfPayloads(
                    regex) >= RegexPayloadGenerator.DEFAULT_LIMIT_CALCULATION_PAYLOADS) {
                JOptionPane.showMessageDialog(
                        null,
                        Constant.messages.getString("fuzz.payloads.generator.regex.warnMaxNumberOfPayloads.message"),
                        Constant.messages.getString("fuzz.payloads.generator.regex.warnMaxNumberOfPayloads.title"),
                        JOptionPane.INFORMATION_MESSAGE);
            }
            oldGenerator = null;
            return true;
        }

        private int calculateNumberOfPayloads(String regex) {
            return RegexPayloadGenerator.calculateNumberOfPayloads(
                    regex,
                    getMaximumForPayloadCalculation(getMaxPayloadsNumberSpinner().getValue().intValue()));
        }

        @Override
        public String getHelpTarget() {
            // THC add help page...
            return null;
        }

        private static int getMaximumForPayloadPersistence(int limit) {
            if (limit == 0) {
                return MAX_NUMBER_PAYLOADS_PERSISTENCE;
            }
            return Math.min(limit, MAX_NUMBER_PAYLOADS_PERSISTENCE);
        }
    }

    private static int getMaximumForPayloadCalculation(int limit) {
        if (limit == 0) {
            return RegexPayloadGenerator.DEFAULT_LIMIT_CALCULATION_PAYLOADS;
        }
        return Math.min(limit, RegexPayloadGenerator.DEFAULT_LIMIT_CALCULATION_PAYLOADS);
    }
}
