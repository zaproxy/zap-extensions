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

import javax.swing.ButtonGroup;
import javax.swing.GroupLayout;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;
import org.zaproxy.zap.extension.fuzz.payloads.processor.ExpandStringProcessor;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.ExpandStringProcessorUIHandler.ExpandStringProcessorUI;
import org.zaproxy.zap.model.MessageLocation;
import org.zaproxy.zap.utils.ZapNumberSpinner;
import org.zaproxy.zap.utils.ZapTextField;

public class ExpandStringProcessorUIHandler
        implements PayloadProcessorUIHandler<
                DefaultPayload, ExpandStringProcessor, ExpandStringProcessorUI> {

    private static final String PROCESSOR_NAME =
            Constant.messages.getString("fuzz.payload.processor.expand.name");

    @Override
    public String getName() {
        return PROCESSOR_NAME;
    }

    @Override
    public Class<ExpandStringProcessorUI> getPayloadProcessorUIClass() {
        return ExpandStringProcessorUI.class;
    }

    @Override
    public Class<ExpandStringProcessorUIPanel> getPayloadProcessorUIPanelClass() {
        return ExpandStringProcessorUIPanel.class;
    }

    @Override
    public ExpandStringProcessorUIPanel createPanel() {
        return new ExpandStringProcessorUIPanel();
    }

    public static class ExpandStringProcessorUI
            implements PayloadProcessorUI<DefaultPayload, ExpandStringProcessor> {

        private final boolean begin;
        private final String value;
        private final int length;

        public ExpandStringProcessorUI(boolean begin, String value, int length) {
            this.begin = begin;
            this.value = value;
            this.length = length;
        }

        public boolean isBegin() {
            return begin;
        }

        public String getValue() {
            return value;
        }

        public int getLength() {
            return length;
        }

        @Override
        public Class<ExpandStringProcessor> getPayloadProcessorClass() {
            return ExpandStringProcessor.class;
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
            String positionMessage =
                    begin
                            ? Constant.messages.getString(
                                    "fuzz.payload.processor.expand.description.position.begin")
                            : Constant.messages.getString(
                                    "fuzz.payload.processor.expand.description.position.end");

            return Constant.messages.getString(
                    "fuzz.payload.processor.expand.description",
                    Integer.valueOf(getLength()),
                    getValue(),
                    positionMessage);
        }

        @Override
        public ExpandStringProcessor getPayloadProcessor() {
            ExpandStringProcessor.Position position =
                    (isBegin()
                            ? ExpandStringProcessor.Position.BEGIN
                            : ExpandStringProcessor.Position.END);
            return new ExpandStringProcessor(position, getValue(), getLength());
        }

        @Override
        public ExpandStringProcessorUI copy() {
            return this;
        }
    }

    public static class ExpandStringProcessorUIPanel
            implements PayloadProcessorUIPanel<
                    DefaultPayload, ExpandStringProcessor, ExpandStringProcessorUI> {

        private static final String POSITION_FIELD_LABEL =
                Constant.messages.getString("fuzz.payload.processor.expand.position.label");
        private static final String BEGIN_POSITION_FIELD_LABEL =
                Constant.messages.getString("fuzz.payload.processor.expand.position.begin.label");
        private static final String END_POSITION_FIELD_LABEL =
                Constant.messages.getString("fuzz.payload.processor.expand.position.end.label");

        private static final String VALUE_FIELD_LABEL =
                Constant.messages.getString("fuzz.payload.processor.expand.value.label");

        private static final String LENGTH_FIELD_LABEL =
                Constant.messages.getString("fuzz.payload.processor.expand.length.label");

        private JPanel fieldsPanel;

        private JRadioButton beginPositionRadioButton;
        private JRadioButton endPositionRadioButton;
        private ZapTextField valueTextField;
        private ZapNumberSpinner lengthNumberSpinner;

        public ExpandStringProcessorUIPanel() {
            fieldsPanel = new JPanel();

            GroupLayout layout = new GroupLayout(fieldsPanel);
            fieldsPanel.setLayout(layout);
            layout.setAutoCreateGaps(true);

            ButtonGroup positionsButtonGroup = new ButtonGroup();
            positionsButtonGroup.add(getBeginPositionRadioButton());
            positionsButtonGroup.add(getEndPositionRadioButton());

            getBeginPositionRadioButton().setSelected(true);

            JLabel positionLabel = new JLabel(POSITION_FIELD_LABEL);
            positionLabel.setLabelFor(getBeginPositionRadioButton());

            JLabel valueLabel = new JLabel(VALUE_FIELD_LABEL);
            valueLabel.setLabelFor(getValueTextField());

            JLabel lengthLabel = new JLabel(LENGTH_FIELD_LABEL);
            lengthLabel.setLabelFor(getLengthNumberSpinner());

            layout.setHorizontalGroup(
                    layout.createSequentialGroup()
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                            .addComponent(positionLabel)
                                            .addComponent(valueLabel)
                                            .addComponent(lengthLabel))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                            .addGroup(
                                                    layout.createParallelGroup(
                                                                    GroupLayout.Alignment.LEADING)
                                                            .addComponent(
                                                                    getBeginPositionRadioButton())
                                                            .addComponent(
                                                                    getEndPositionRadioButton()))
                                            .addComponent(getValueTextField())
                                            .addComponent(getLengthNumberSpinner())));

            layout.setVerticalGroup(
                    layout.createSequentialGroup()
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(positionLabel)
                                            .addGroup(
                                                    GroupLayout.Alignment.BASELINE,
                                                    layout.createSequentialGroup()
                                                            .addComponent(
                                                                    getBeginPositionRadioButton())
                                                            .addComponent(
                                                                    getEndPositionRadioButton())))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(valueLabel)
                                            .addComponent(getValueTextField()))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(lengthLabel)
                                            .addComponent(getLengthNumberSpinner())));
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

        private JRadioButton getBeginPositionRadioButton() {
            if (beginPositionRadioButton == null) {
                beginPositionRadioButton = new JRadioButton(BEGIN_POSITION_FIELD_LABEL);
            }
            return beginPositionRadioButton;
        }

        private JRadioButton getEndPositionRadioButton() {
            if (endPositionRadioButton == null) {
                endPositionRadioButton = new JRadioButton(END_POSITION_FIELD_LABEL);
            }
            return endPositionRadioButton;
        }

        private ZapNumberSpinner getLengthNumberSpinner() {
            if (lengthNumberSpinner == null) {
                lengthNumberSpinner = new ZapNumberSpinner(1, 1, Integer.MAX_VALUE);
            }
            return lengthNumberSpinner;
        }

        @Override
        public void init(MessageLocation messageLocation) {
            getLengthNumberSpinner().setValue(Math.max(messageLocation.getValue().length(), 1));
        }

        @Override
        public ExpandStringProcessorUI getPayloadProcessorUI() {
            return new ExpandStringProcessorUI(
                    getBeginPositionRadioButton().isSelected(),
                    getValueTextField().getText(),
                    getLengthNumberSpinner().getValue().intValue());
        }

        @Override
        public void setPayloadProcessorUI(ExpandStringProcessorUI payloadProcessorUI) {
            if (payloadProcessorUI.isBegin()) {
                getBeginPositionRadioButton().setSelected(true);
            } else {
                getEndPositionRadioButton().setSelected(true);
            }
            getValueTextField().setText(payloadProcessorUI.getValue());
            getLengthNumberSpinner().setValue(payloadProcessorUI.getLength());
        }

        @Override
        public void clear() {
            getValueTextField().setText("");
            getValueTextField().discardAllEdits();
            getBeginPositionRadioButton().setSelected(true);
            getLengthNumberSpinner().setValue(1);
        }

        @Override
        public boolean validate() {
            if (getValueTextField().getText().isEmpty()) {
                JOptionPane.showMessageDialog(
                        null,
                        Constant.messages.getString(
                                "fuzz.payload.processor.expand.warnNoValue.message"),
                        Constant.messages.getString(
                                "fuzz.payload.processor.expand.warnNoValue.title"),
                        JOptionPane.INFORMATION_MESSAGE);
                getValueTextField().requestFocusInWindow();
                return false;
            }
            return true;
        }

        @Override
        public ExpandStringProcessor getPayloadProcessor() {
            if (!validate()) {
                return null;
            }
            ExpandStringProcessor.Position position =
                    (getBeginPositionRadioButton().isSelected()
                            ? ExpandStringProcessor.Position.BEGIN
                            : ExpandStringProcessor.Position.END);
            return new ExpandStringProcessor(
                    position,
                    getValueTextField().getText(),
                    getLengthNumberSpinner().getValue().intValue());
        }

        @Override
        public String getHelpTarget() {
            return "addon.fuzzer.processors";
        }
    }
}
