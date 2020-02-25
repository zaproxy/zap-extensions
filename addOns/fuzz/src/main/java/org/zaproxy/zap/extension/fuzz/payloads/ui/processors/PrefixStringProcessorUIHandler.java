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
package org.zaproxy.zap.extension.fuzz.payloads.ui.processors;

import javax.swing.GroupLayout;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;
import org.zaproxy.zap.extension.fuzz.payloads.processor.PrefixStringProcessor;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.PrefixStringProcessorUIHandler.PrefixStringProcessorUI;
import org.zaproxy.zap.utils.ZapTextField;

public class PrefixStringProcessorUIHandler
        implements PayloadProcessorUIHandler<
                DefaultPayload, PrefixStringProcessor, PrefixStringProcessorUI> {

    private static final String PROCESSOR_NAME =
            Constant.messages.getString("fuzz.payload.processor.prefixString.name");

    @Override
    public String getName() {
        return PROCESSOR_NAME;
    }

    @Override
    public Class<PrefixStringProcessorUI> getPayloadProcessorUIClass() {
        return PrefixStringProcessorUI.class;
    }

    @Override
    public Class<PrefixStringProcessorUIPanel> getPayloadProcessorUIPanelClass() {
        return PrefixStringProcessorUIPanel.class;
    }

    @Override
    public PrefixStringProcessorUIPanel createPanel() {
        return new PrefixStringProcessorUIPanel();
    }

    public static class PrefixStringProcessorUI
            implements PayloadProcessorUI<DefaultPayload, PrefixStringProcessor> {

        private final String value;

        public PrefixStringProcessorUI(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }

        @Override
        public Class<PrefixStringProcessor> getPayloadProcessorClass() {
            return PrefixStringProcessor.class;
        }

        @Override
        public String getName() {
            return PROCESSOR_NAME;
        }

        @Override
        public boolean isMutable() {
            return true;
        }

        @Override
        public String getDescription() {
            return value;
        }

        @Override
        public PrefixStringProcessor getPayloadProcessor() {
            return new PrefixStringProcessor(value);
        }

        @Override
        public PrefixStringProcessorUI copy() {
            return this;
        }
    }

    public static class PrefixStringProcessorUIPanel
            extends AbstractProcessorUIPanel<
                    DefaultPayload, PrefixStringProcessor, PrefixStringProcessorUI> {

        private static final String VALUE_FIELD_LABEL =
                Constant.messages.getString("fuzz.payload.processor.prefixString.value.label");

        private JPanel fieldsPanel;

        private ZapTextField valueTextField;

        public PrefixStringProcessorUIPanel() {
            fieldsPanel = new JPanel();

            GroupLayout layout = new GroupLayout(fieldsPanel);
            fieldsPanel.setLayout(layout);
            layout.setAutoCreateGaps(true);

            JLabel valueLabel = new JLabel(VALUE_FIELD_LABEL);
            valueLabel.setLabelFor(getValueTextField());

            layout.setHorizontalGroup(
                    layout.createSequentialGroup()
                            .addComponent(valueLabel)
                            .addComponent(getValueTextField()));

            layout.setVerticalGroup(
                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                            .addComponent(valueLabel)
                            .addComponent(getValueTextField()));
        }

        @Override
        public JPanel getComponent() {
            return fieldsPanel;
        }

        private ZapTextField getValueTextField() {
            if (valueTextField == null) {
                valueTextField = new ZapTextField();
                valueTextField.setColumns(25);
            }
            return valueTextField;
        }

        @Override
        public PrefixStringProcessorUI getPayloadProcessorUI() {
            return new PrefixStringProcessorUI(getValueTextField().getText());
        }

        @Override
        public void setPayloadProcessorUI(PrefixStringProcessorUI payloadProcessorUI) {
            getValueTextField().setText(payloadProcessorUI.getValue());
        }

        @Override
        public void clear() {
            getValueTextField().setText("");
            getValueTextField().discardAllEdits();
        }

        @Override
        public boolean validate() {
            if (getValueTextField().getText().isEmpty()) {
                JOptionPane.showMessageDialog(
                        null,
                        Constant.messages.getString(
                                "fuzz.payload.processor.prefixString.warnNoValue.message"),
                        Constant.messages.getString(
                                "fuzz.payload.processor.prefixString.warnNoValue.title"),
                        JOptionPane.INFORMATION_MESSAGE);
                getValueTextField().requestFocusInWindow();
                return false;
            }
            return true;
        }

        @Override
        public PrefixStringProcessor getPayloadProcessor() {
            if (!validate()) {
                return null;
            }
            return new PrefixStringProcessor(getValueTextField().getText());
        }
    }
}
