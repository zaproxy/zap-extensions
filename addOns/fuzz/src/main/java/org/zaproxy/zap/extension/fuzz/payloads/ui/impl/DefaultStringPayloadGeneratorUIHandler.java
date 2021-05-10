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

import java.awt.event.ItemEvent;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.GroupLayout;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;
import org.zaproxy.zap.extension.fuzz.payloads.generator.DefaultStringPayloadGenerator;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUI;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUIHandler;
import org.zaproxy.zap.extension.fuzz.payloads.ui.impl.DefaultStringPayloadGeneratorUIHandler.DefaultStringPayloadGeneratorUI;
import org.zaproxy.zap.model.MessageLocation;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.utils.StringUIUtils;
import org.zaproxy.zap.utils.ZapTextArea;

public class DefaultStringPayloadGeneratorUIHandler
        implements PayloadGeneratorUIHandler<
                DefaultPayload, DefaultStringPayloadGenerator, DefaultStringPayloadGeneratorUI> {

    private static final String PAYLOAD_GENERATOR_NAME =
            Constant.messages.getString("fuzz.payloads.generator.strings.name");

    private static final String SPLIT_PAYLOADS_PATTERN = "\r?\n";

    @Override
    public String getName() {
        return PAYLOAD_GENERATOR_NAME;
    }

    @Override
    public Class<DefaultStringPayloadGeneratorUI> getPayloadGeneratorUIClass() {
        return DefaultStringPayloadGeneratorUI.class;
    }

    @Override
    public Class<DefaultStringPayloadGeneratorUIPanel> getPayloadGeneratorUIPanelClass() {
        return DefaultStringPayloadGeneratorUIPanel.class;
    }

    @Override
    public DefaultStringPayloadGeneratorUIPanel createPanel() {
        return new DefaultStringPayloadGeneratorUIPanel();
    }

    public static class DefaultStringPayloadGeneratorUI
            implements PayloadGeneratorUI<DefaultPayload, DefaultStringPayloadGenerator> {

        private final boolean multiline;
        private final String value;

        public DefaultStringPayloadGeneratorUI(String value, boolean multiline) {
            this.value = value;
            this.multiline = multiline;
        }

        public String getValue() {
            return value;
        }

        public boolean isMultiline() {
            return multiline;
        }

        @Override
        public Class<DefaultStringPayloadGenerator> getPayloadGeneratorClass() {
            return DefaultStringPayloadGenerator.class;
        }

        @Override
        public String getName() {
            return PAYLOAD_GENERATOR_NAME;
        }

        @Override
        public String getDescription() {
            StringBuilder descriptionBuilder = new StringBuilder(150);

            if (multiline) {
                String text = StringUIUtils.replaceWithVisibleWhiteSpaceChars(value);
                descriptionBuilder.append(text, 0, Math.min(text.length(), 101));
            } else {
                for (String payload : Arrays.asList(value.split(SPLIT_PAYLOADS_PATTERN))) {
                    if (descriptionBuilder.length() > 100) {
                        break;
                    }
                    if (descriptionBuilder.length() > 0) {
                        descriptionBuilder.append(", ");
                    }
                    descriptionBuilder.append(payload);
                }
            }

            if (descriptionBuilder.length() > 100) {
                descriptionBuilder.setLength(100);
                descriptionBuilder.replace(97, 100, "...");
            }

            return descriptionBuilder.toString();
        }

        @Override
        public long getNumberOfPayloads() {
            if (multiline) {
                return 1;
            }
            int payloads = 1;
            Matcher matcher = Pattern.compile(SPLIT_PAYLOADS_PATTERN).matcher(value);
            while (matcher.find()) {
                payloads++;
            }
            return payloads;
        }

        @Override
        public DefaultStringPayloadGenerator getPayloadGenerator() {
            if (multiline) {
                return new DefaultStringPayloadGenerator(value);
            }
            return new DefaultStringPayloadGenerator(Arrays.asList(value.split("\r?\n", -1)));
        }

        @Override
        public DefaultStringPayloadGeneratorUI copy() {
            return this;
        }
    }

    public static class DefaultStringPayloadGeneratorUIPanel
            extends AbstractPersistentPayloadGeneratorUIPanel<
                    DefaultPayload,
                    DefaultStringPayloadGenerator,
                    DefaultStringPayloadGeneratorUI> {

        private static final String CONTENTS_FIELD_LABEL =
                Constant.messages.getString("fuzz.payloads.generator.strings.contents.label");
        private static final String MULTILINE_FIELD_LABEL =
                Constant.messages.getString("fuzz.payloads.generator.strings.multiline.label");
        private static final String MULTILINE_FIELD_TOOLTIP =
                Constant.messages.getString("fuzz.payloads.generator.strings.multiline.tooltip");

        private JPanel fieldsPanel;

        private ZapTextArea contentsTextArea;
        private JCheckBox multilineCheckBox;

        public DefaultStringPayloadGeneratorUIPanel() {
            fieldsPanel = new JPanel();

            GroupLayout layout = new GroupLayout(fieldsPanel);
            fieldsPanel.setLayout(layout);
            layout.setAutoCreateGaps(true);

            JLabel contentsLabel = new JLabel(CONTENTS_FIELD_LABEL);
            contentsLabel.setLabelFor(getContentsTextArea());
            JLabel multilineLabel = new JLabel(MULTILINE_FIELD_LABEL);
            multilineLabel.setLabelFor(getMultilineCheckBox());
            multilineLabel.setToolTipText(MULTILINE_FIELD_TOOLTIP);

            JScrollPane contentsScrollPane = new JScrollPane(getContentsTextArea());

            layout.setHorizontalGroup(
                    layout.createSequentialGroup()
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                            .addComponent(contentsLabel)
                                            .addComponent(multilineLabel))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                            .addComponent(contentsScrollPane)
                                            .addComponent(getMultilineCheckBox())
                                            .addComponent(getSaveButton())));

            layout.setVerticalGroup(
                    layout.createSequentialGroup()
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(contentsLabel)
                                            .addComponent(contentsScrollPane))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(multilineLabel)
                                            .addComponent(getMultilineCheckBox()))
                            .addComponent(getSaveButton()));

            getSaveButton().setEnabled(true);
        }

        private ZapTextArea getContentsTextArea() {
            if (contentsTextArea == null) {
                contentsTextArea = new ZapTextArea();
                contentsTextArea.setColumns(25);
                contentsTextArea.setRows(10);
                contentsTextArea.setFont(FontUtils.getFont("Monospaced"));
            }
            return contentsTextArea;
        }

        private JCheckBox getMultilineCheckBox() {
            if (multilineCheckBox == null) {
                multilineCheckBox = new JCheckBox();
                multilineCheckBox.setToolTipText(MULTILINE_FIELD_TOOLTIP);
                multilineCheckBox.addItemListener(
                        e -> getSaveButton().setEnabled(e.getStateChange() != ItemEvent.SELECTED));
            }
            return multilineCheckBox;
        }

        @Override
        public void init(MessageLocation messageLocation) {}

        @Override
        public JPanel getComponent() {
            return fieldsPanel;
        }

        @Override
        public void setPayloadGeneratorUI(DefaultStringPayloadGeneratorUI payloadGeneratorUI) {
            getContentsTextArea().setText(payloadGeneratorUI.getValue());
            getMultilineCheckBox().setSelected(payloadGeneratorUI.isMultiline());
        }

        @Override
        public DefaultStringPayloadGeneratorUI getPayloadGeneratorUI() {
            return new DefaultStringPayloadGeneratorUI(
                    getContentsTextArea().getText(), getMultilineCheckBox().isSelected());
        }

        @Override
        protected DefaultStringPayloadGenerator getPayloadGenerator() {
            return new DefaultStringPayloadGenerator(
                    Arrays.asList(getContentsTextArea().getText().split("\r?\n", -1)));
        }

        @Override
        public void clear() {
            getContentsTextArea().setText("");
            getContentsTextArea().discardAllEdits();
            getMultilineCheckBox().setSelected(false);
        }

        @Override
        public boolean validate() {
            return true;
        }
    }
}
