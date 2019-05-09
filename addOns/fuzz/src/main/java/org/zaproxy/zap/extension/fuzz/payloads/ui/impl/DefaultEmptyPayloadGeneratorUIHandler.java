/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;
import org.zaproxy.zap.extension.fuzz.payloads.generator.EmptyPayloadGenerator;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUI;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUIHandler;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUIPanel;
import org.zaproxy.zap.extension.fuzz.payloads.ui.impl.DefaultEmptyPayloadGeneratorUIHandler.DefaultEmptyPayloadGenerator;
import org.zaproxy.zap.extension.fuzz.payloads.ui.impl.DefaultEmptyPayloadGeneratorUIHandler.DefaultEmptyPayloadGeneratorUI;
import org.zaproxy.zap.model.MessageLocation;
import org.zaproxy.zap.utils.ZapNumberSpinner;

public class DefaultEmptyPayloadGeneratorUIHandler
        implements PayloadGeneratorUIHandler<
                DefaultPayload, DefaultEmptyPayloadGenerator, DefaultEmptyPayloadGeneratorUI> {

    private static final String PAYLOAD_GENERATOR_NAME =
            Constant.messages.getString("fuzz.payloads.generator.empty.name");
    private static final String PAYLOAD_GENERATOR_DESC =
            Constant.messages.getString("fuzz.payloads.generator.empty.description");

    @Override
    public String getName() {
        return PAYLOAD_GENERATOR_NAME;
    }

    @Override
    public Class<DefaultEmptyPayloadGeneratorUI> getPayloadGeneratorUIClass() {
        return DefaultEmptyPayloadGeneratorUI.class;
    }

    @Override
    public Class<DefaultEmptyPayloadGeneratorUIPanel> getPayloadGeneratorUIPanelClass() {
        return DefaultEmptyPayloadGeneratorUIPanel.class;
    }

    @Override
    public DefaultEmptyPayloadGeneratorUIPanel createPanel() {
        return new DefaultEmptyPayloadGeneratorUIPanel();
    }

    public static class DefaultEmptyPayloadGeneratorUI
            implements PayloadGeneratorUI<DefaultPayload, DefaultEmptyPayloadGenerator> {

        private final String value;
        private final int repetitions;

        public DefaultEmptyPayloadGeneratorUI(String value, int repetitions) {
            this.value = value;
            this.repetitions = repetitions;
        }

        public String getValue() {
            return value;
        }

        public int getRepetitions() {
            return repetitions;
        }

        @Override
        public Class<DefaultEmptyPayloadGenerator> getPayloadGeneratorClass() {
            return DefaultEmptyPayloadGenerator.class;
        }

        @Override
        public String getName() {
            return PAYLOAD_GENERATOR_NAME;
        }

        @Override
        public String getDescription() {
            return MessageFormat.format(PAYLOAD_GENERATOR_DESC, repetitions);
        }

        @Override
        public long getNumberOfPayloads() {
            return repetitions;
        }

        @Override
        public DefaultEmptyPayloadGenerator getPayloadGenerator() {
            return new DefaultEmptyPayloadGenerator(new DefaultPayload(value), repetitions);
        }

        @Override
        public DefaultEmptyPayloadGeneratorUI copy() {
            return this;
        }
    }

    public static class DefaultEmptyPayloadGeneratorUIPanel
            implements PayloadGeneratorUIPanel<
                    DefaultPayload, DefaultEmptyPayloadGenerator, DefaultEmptyPayloadGeneratorUI> {

        private static final String NUMBER_REPETITIONS_FIELD_LABEL =
                Constant.messages.getString("fuzz.payloads.generator.empty.repetitions.label");

        private static final int DEFAULT_NUMBER_REPETITIONS = 10;

        private JPanel fieldsPanel;

        private ZapNumberSpinner repetitionsNumberSpinner;

        private String payloadValue;

        public DefaultEmptyPayloadGeneratorUIPanel() {
            fieldsPanel = new JPanel();

            GroupLayout layout = new GroupLayout(fieldsPanel);
            fieldsPanel.setLayout(layout);
            layout.setAutoCreateGaps(true);

            JLabel valueLabel = new JLabel(NUMBER_REPETITIONS_FIELD_LABEL);
            valueLabel.setLabelFor(getRepetitionsNumberSpinner());

            layout.setHorizontalGroup(
                    layout.createSequentialGroup()
                            .addComponent(valueLabel)
                            .addComponent(getRepetitionsNumberSpinner()));

            layout.setVerticalGroup(
                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                            .addComponent(valueLabel)
                            .addComponent(getRepetitionsNumberSpinner()));
        }

        private ZapNumberSpinner getRepetitionsNumberSpinner() {
            if (repetitionsNumberSpinner == null) {
                repetitionsNumberSpinner =
                        new ZapNumberSpinner(1, DEFAULT_NUMBER_REPETITIONS, Integer.MAX_VALUE);
            }
            return repetitionsNumberSpinner;
        }

        @Override
        public void init(MessageLocation messageLocation) {
            payloadValue = messageLocation.getValue();
        }

        @Override
        public JPanel getComponent() {
            return fieldsPanel;
        }

        @Override
        public void setPayloadGeneratorUI(DefaultEmptyPayloadGeneratorUI payloadGeneratorUI) {
            getRepetitionsNumberSpinner().setValue(payloadGeneratorUI.getRepetitions());
        }

        @Override
        public DefaultEmptyPayloadGeneratorUI getPayloadGeneratorUI() {
            return new DefaultEmptyPayloadGeneratorUI(
                    payloadValue, getRepetitionsNumberSpinner().getValue());
        }

        @Override
        public void clear() {
            getRepetitionsNumberSpinner().setValue(DEFAULT_NUMBER_REPETITIONS);
        }

        @Override
        public boolean validate() {
            return true;
        }

        @Override
        public String getHelpTarget() {
            return "addon.fuzzer.payloads";
        }
    }

    public static class DefaultEmptyPayloadGenerator extends EmptyPayloadGenerator<DefaultPayload> {

        public DefaultEmptyPayloadGenerator(DefaultPayload value, int numberOfPayloads) {
            super(value, numberOfPayloads);
        }
    }
}
