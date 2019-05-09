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
import org.zaproxy.zap.extension.fuzz.payloads.processor.PostfixStringProcessor;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.PostfixStringProcessorUIHandler.PostfixStringProcessorUI;
import org.zaproxy.zap.utils.ZapTextField;

public class PostfixStringProcessorUIHandler
        implements PayloadProcessorUIHandler<
                DefaultPayload, PostfixStringProcessor, PostfixStringProcessorUI> {

    private static final String PROCESSOR_NAME =
            Constant.messages.getString("fuzz.payload.processor.postfixString.name");

    @Override
    public String getName() {
        return PROCESSOR_NAME;
    }

    @Override
    public Class<PostfixStringProcessorUI> getPayloadProcessorUIClass() {
        return PostfixStringProcessorUI.class;
    }

    @Override
    public Class<PostfixStringProcessorUIPanel> getPayloadProcessorUIPanelClass() {
        return PostfixStringProcessorUIPanel.class;
    }

    @Override
    public PostfixStringProcessorUIPanel createPanel() {
        return new PostfixStringProcessorUIPanel();
    }

    public static class PostfixStringProcessorUI
            implements PayloadProcessorUI<DefaultPayload, PostfixStringProcessor> {

        private final String value;

        public PostfixStringProcessorUI(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }

        @Override
        public Class<PostfixStringProcessor> getPayloadProcessorClass() {
            return PostfixStringProcessor.class;
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
        public PostfixStringProcessor getPayloadProcessor() {
            return new PostfixStringProcessor(value);
        }

        @Override
        public PostfixStringProcessorUI copy() {
            return this;
        }
    }

    public static class PostfixStringProcessorUIPanel
            extends AbstractProcessorUIPanel<
                    DefaultPayload, PostfixStringProcessor, PostfixStringProcessorUI> {

        private static final String VALUE_FIELD_LABEL =
                Constant.messages.getString("fuzz.payload.processor.postfixString.value.label");

        private JPanel fieldsPanel;

        private ZapTextField valueTextField;

        public PostfixStringProcessorUIPanel() {
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
        public PostfixStringProcessorUI getPayloadProcessorUI() {
            return new PostfixStringProcessorUI(getValueTextField().getText());
        }

        @Override
        public void setPayloadProcessorUI(PostfixStringProcessorUI payloadProcessorUI) {
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
                                "fuzz.payload.processor.postfixString.warnNoValue.message"),
                        Constant.messages.getString(
                                "fuzz.payload.processor.postfixString.warnNoValue.title"),
                        JOptionPane.INFORMATION_MESSAGE);
                getValueTextField().requestFocusInWindow();
                return false;
            }
            return true;
        }

        @Override
        public PostfixStringProcessor getPayloadProcessor() {
            if (!validate()) {
                return null;
            }
            return new PostfixStringProcessor(getValueTextField().getText());
        }
    }
}
