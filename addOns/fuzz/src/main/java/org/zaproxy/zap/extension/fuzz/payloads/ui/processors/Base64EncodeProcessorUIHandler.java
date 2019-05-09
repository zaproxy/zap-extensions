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

import java.nio.charset.Charset;
import javax.swing.GroupLayout;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;
import org.zaproxy.zap.extension.fuzz.payloads.processor.Base64EncodeProcessor;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.AbstractCharsetProcessorUIPanel.AbstractCharsetProcessorUI;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.Base64EncodeProcessorUIHandler.Base64EncodeProcessorUI;

public class Base64EncodeProcessorUIHandler
        implements PayloadProcessorUIHandler<
                DefaultPayload, Base64EncodeProcessor, Base64EncodeProcessorUI> {

    private static final String PROCESSOR_NAME =
            Constant.messages.getString("fuzz.payload.processor.base64Encode.name");

    @Override
    public String getName() {
        return PROCESSOR_NAME;
    }

    @Override
    public Class<Base64EncodeProcessorUI> getPayloadProcessorUIClass() {
        return Base64EncodeProcessorUI.class;
    }

    @Override
    public Class<Base64EncodeProcessorUIPanel> getPayloadProcessorUIPanelClass() {
        return Base64EncodeProcessorUIPanel.class;
    }

    @Override
    public Base64EncodeProcessorUIPanel createPanel() {
        return new Base64EncodeProcessorUIPanel();
    }

    public static class Base64EncodeProcessorUI
            extends AbstractCharsetProcessorUI<DefaultPayload, Base64EncodeProcessor> {

        private final boolean breakLines;

        public Base64EncodeProcessorUI(Charset charset, boolean breakLines) {
            super(charset);

            this.breakLines = breakLines;
        }

        public boolean isBreakLines() {
            return breakLines;
        }

        @Override
        public Class<Base64EncodeProcessor> getPayloadProcessorClass() {
            return Base64EncodeProcessor.class;
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
            String breakLinesMessage =
                    isBreakLines()
                            ? Constant.messages.getString(
                                    "fuzz.payload.processor.base64Encode.description.breakLines")
                            : "";

            return Constant.messages.getString(
                    "fuzz.payload.processor.base64Encode.description.base",
                    getCharset().name(),
                    breakLinesMessage);
        }

        @Override
        public Base64EncodeProcessor getPayloadProcessor() {
            return new Base64EncodeProcessor(getCharset(), breakLines);
        }

        @Override
        public Base64EncodeProcessorUI copy() {
            return this;
        }
    }

    public static class Base64EncodeProcessorUIPanel
            extends AbstractCharsetProcessorUIPanel<
                    DefaultPayload, Base64EncodeProcessor, Base64EncodeProcessorUI> {

        private static final String BREAK_LINES_FIELD_LABEL =
                Constant.messages.getString("fuzz.payload.processor.base64Encode.breakLines.label");

        private static final String BREAK_LINES_FIELD_TOOLTIP =
                Constant.messages.getString(
                        "fuzz.payload.processor.base64Encode.breakLines.tooltip");

        private JPanel fieldsPanel;

        private JCheckBox breakLinesCheckBox;

        public Base64EncodeProcessorUIPanel() {
            fieldsPanel = new JPanel();

            GroupLayout layout = new GroupLayout(fieldsPanel);
            fieldsPanel.setLayout(layout);
            layout.setAutoCreateGaps(true);

            JLabel breakLinesLabel = new JLabel(BREAK_LINES_FIELD_LABEL);
            breakLinesLabel.setLabelFor(getBreakLinesCheckBox());
            breakLinesLabel.setToolTipText(BREAK_LINES_FIELD_TOOLTIP);

            layout.setHorizontalGroup(
                    layout.createSequentialGroup()
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                            .addComponent(getCharsetLabel())
                                            .addComponent(breakLinesLabel))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                            .addComponent(getCharsetComboBox())
                                            .addComponent(getBreakLinesCheckBox())));

            layout.setVerticalGroup(
                    layout.createSequentialGroup()
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(getCharsetLabel())
                                            .addComponent(getCharsetComboBox()))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(breakLinesLabel)
                                            .addComponent(getBreakLinesCheckBox())));
        }

        @Override
        public JPanel getComponent() {
            return fieldsPanel;
        }

        private JCheckBox getBreakLinesCheckBox() {
            if (breakLinesCheckBox == null) {
                breakLinesCheckBox = new JCheckBox();
            }
            return breakLinesCheckBox;
        }

        @Override
        public void clear() {
            super.clear();
            getBreakLinesCheckBox().setSelected(false);
        }

        @Override
        public Base64EncodeProcessorUI getPayloadProcessorUI() {
            return new Base64EncodeProcessorUI(
                    (Charset) getCharsetComboBox().getSelectedItem(),
                    getBreakLinesCheckBox().isSelected());
        }

        @Override
        public void setPayloadProcessorUI(Base64EncodeProcessorUI payloadProcessorUI) {
            super.setPayloadProcessorUI(payloadProcessorUI);
            getBreakLinesCheckBox().setSelected(payloadProcessorUI.isBreakLines());
        }

        @Override
        public Base64EncodeProcessor getPayloadProcessor() {
            return new Base64EncodeProcessor(
                    (Charset) getCharsetComboBox().getSelectedItem(),
                    getBreakLinesCheckBox().isSelected());
        }
    }
}
