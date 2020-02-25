/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
import org.zaproxy.zap.extension.fuzz.payloads.processor.AbstractStringHashProcessor;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.AbstractStringHashProcessorUIPanel.AbstractStringHashProcessorUI;

public abstract class AbstractStringHashProcessorUIPanel<
                T1 extends AbstractStringHashProcessor,
                T2 extends AbstractStringHashProcessorUI<T1>>
        extends AbstractCharsetProcessorUIPanel<DefaultPayload, T1, T2> {

    protected static final String UPPER_CASE_FIELD_LABEL =
            Constant.messages.getString("fuzz.payload.processor.hash.upperCase.label");

    private JLabel upperCaseLabel;
    private JCheckBox upperCaseCheckBox;

    public AbstractStringHashProcessorUIPanel() {}

    protected JLabel getUpperCaseLabel() {
        if (upperCaseLabel == null) {
            upperCaseLabel = new JLabel(UPPER_CASE_FIELD_LABEL);
            upperCaseLabel.setLabelFor(getUpperCaseCheckBox());
        }
        return upperCaseLabel;
    }

    protected JCheckBox getUpperCaseCheckBox() {
        if (upperCaseCheckBox == null) {
            upperCaseCheckBox = new JCheckBox();
        }
        return upperCaseCheckBox;
    }

    @Override
    public void clear() {
        super.clear();
        getUpperCaseCheckBox().setSelected(false);
    }

    @Override
    public void setPayloadProcessorUI(T2 payloadProcessorUI) {
        super.setPayloadProcessorUI(payloadProcessorUI);
        getUpperCaseCheckBox().setSelected(payloadProcessorUI.isUpperCase());
    }

    @Override
    protected JPanel createDefaultFieldsPanel() {
        JPanel fieldsPanel = new JPanel();

        GroupLayout layout = new GroupLayout(fieldsPanel);
        fieldsPanel.setLayout(layout);
        layout.setAutoCreateGaps(true);

        layout.setHorizontalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                        .addComponent(getCharsetLabel())
                                        .addComponent(getUpperCaseLabel()))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                        .addComponent(getCharsetComboBox())
                                        .addComponent(getUpperCaseCheckBox())));

        layout.setVerticalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(getCharsetLabel())
                                        .addComponent(getCharsetComboBox()))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(getUpperCaseLabel())
                                        .addComponent(getUpperCaseCheckBox())));

        return fieldsPanel;
    }

    public abstract static class AbstractStringHashProcessorUI<
                    T extends AbstractStringHashProcessor>
            extends AbstractCharsetProcessorUI<DefaultPayload, T> {

        private final boolean upperCase;

        public AbstractStringHashProcessorUI(Charset charset, boolean upperCase) {
            super(charset);
            this.upperCase = upperCase;
        }

        public boolean isUpperCase() {
            return upperCase;
        }
    }
}
