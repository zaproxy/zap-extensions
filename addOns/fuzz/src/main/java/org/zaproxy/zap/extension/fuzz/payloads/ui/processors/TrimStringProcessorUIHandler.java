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
import javax.swing.JPanel;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;
import org.zaproxy.zap.extension.fuzz.payloads.processor.TrimStringProcessor;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.TrimStringProcessorUIHandler.TrimStringProcessorUI;
import org.zaproxy.zap.model.MessageLocation;
import org.zaproxy.zap.utils.ZapNumberSpinner;

public class TrimStringProcessorUIHandler
        implements PayloadProcessorUIHandler<
                DefaultPayload, TrimStringProcessor, TrimStringProcessorUI> {

    private static final String PROCESSOR_NAME =
            Constant.messages.getString("fuzz.payload.processor.trim.name");

    @Override
    public String getName() {
        return PROCESSOR_NAME;
    }

    @Override
    public Class<TrimStringProcessorUI> getPayloadProcessorUIClass() {
        return TrimStringProcessorUI.class;
    }

    @Override
    public Class<TrimStringProcessorUIPanel> getPayloadProcessorUIPanelClass() {
        return TrimStringProcessorUIPanel.class;
    }

    @Override
    public TrimStringProcessorUIPanel createPanel() {
        return new TrimStringProcessorUIPanel();
    }

    public static class TrimStringProcessorUI
            implements PayloadProcessorUI<DefaultPayload, TrimStringProcessor> {

        private final int length;

        public TrimStringProcessorUI(int length) {
            this.length = length;
        }

        public int getLength() {
            return length;
        }

        @Override
        public Class<TrimStringProcessor> getPayloadProcessorClass() {
            return TrimStringProcessor.class;
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
            return Constant.messages.getString(
                    "fuzz.payload.processor.trim.description", Integer.valueOf(getLength()));
        }

        @Override
        public TrimStringProcessor getPayloadProcessor() {
            return new TrimStringProcessor(length);
        }

        @Override
        public TrimStringProcessorUI copy() {
            return this;
        }
    }

    public static class TrimStringProcessorUIPanel
            extends AbstractProcessorUIPanel<
                    DefaultPayload, TrimStringProcessor, TrimStringProcessorUI> {

        private static final String LENGTH_FIELD_LABEL =
                Constant.messages.getString("fuzz.payload.processor.expand.length.label");

        private JPanel fieldsPanel;

        private ZapNumberSpinner lengthNumberSpinner;

        public TrimStringProcessorUIPanel() {
            fieldsPanel = new JPanel();

            GroupLayout layout = new GroupLayout(fieldsPanel);
            fieldsPanel.setLayout(layout);
            layout.setAutoCreateGaps(true);

            JLabel lengthLabel = new JLabel(LENGTH_FIELD_LABEL);
            lengthLabel.setLabelFor(getLengthNumberSpinner());

            layout.setHorizontalGroup(
                    layout.createSequentialGroup()
                            .addComponent(lengthLabel)
                            .addComponent(getLengthNumberSpinner()));

            layout.setVerticalGroup(
                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                            .addComponent(lengthLabel)
                            .addComponent(getLengthNumberSpinner()));
        }

        @Override
        public JPanel getComponent() {
            return fieldsPanel;
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
        public TrimStringProcessorUI getPayloadProcessorUI() {
            return new TrimStringProcessorUI(getLengthNumberSpinner().getValue().intValue());
        }

        @Override
        public void setPayloadProcessorUI(TrimStringProcessorUI payloadProcessorUI) {
            getLengthNumberSpinner().setValue(payloadProcessorUI.getLength());
        }

        @Override
        public void clear() {
            getLengthNumberSpinner().setValue(1);
        }

        @Override
        public TrimStringProcessor getPayloadProcessor() {
            return new TrimStringProcessor(getLengthNumberSpinner().getValue().intValue());
        }
    }
}
