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
import java.nio.charset.StandardCharsets;
import javax.swing.DefaultComboBoxModel;
import javax.swing.GroupLayout;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.fuzz.payloads.Payload;
import org.zaproxy.zap.extension.fuzz.payloads.processor.AbstractCharsetProcessor;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.AbstractCharsetProcessorUIPanel.AbstractCharsetProcessorUI;

public abstract class AbstractCharsetProcessorUIPanel<
                T extends Payload,
                T2 extends AbstractCharsetProcessor<T>,
                T3 extends AbstractCharsetProcessorUI<T, T2>>
        extends AbstractProcessorUIPanel<T, T2, T3> {

    protected static final String CHARSET_FIELD_LABEL =
            Constant.messages.getString("fuzz.payload.processor.charset.charset.label");

    private static final Charset[] CHARSETS = {
        StandardCharsets.UTF_8, StandardCharsets.ISO_8859_1, StandardCharsets.US_ASCII
    };

    private JLabel charsetLabel;
    private JComboBox<Charset> charsetComboBox;

    public AbstractCharsetProcessorUIPanel() {}

    protected JLabel getCharsetLabel() {
        if (charsetLabel == null) {
            charsetLabel = new JLabel(CHARSET_FIELD_LABEL);
            charsetLabel.setLabelFor(getCharsetComboBox());
        }
        return charsetLabel;
    }

    protected JComboBox<Charset> getCharsetComboBox() {
        if (charsetComboBox == null) {
            charsetComboBox = new JComboBox<>(new DefaultComboBoxModel<>(CHARSETS));
        }
        return charsetComboBox;
    }

    @Override
    public void clear() {
        getCharsetComboBox().setSelectedIndex(0);
    }

    @Override
    public void setPayloadProcessorUI(T3 payloadProcessorUI) {
        getCharsetComboBox().setSelectedItem(payloadProcessorUI.getCharset());
    }

    protected JPanel createDefaultFieldsPanel() {
        JPanel fieldsPanel = new JPanel();

        GroupLayout layout = new GroupLayout(fieldsPanel);
        fieldsPanel.setLayout(layout);
        layout.setAutoCreateGaps(true);

        layout.setHorizontalGroup(
                layout.createSequentialGroup()
                        .addComponent(getCharsetLabel())
                        .addComponent(getCharsetComboBox()));

        layout.setVerticalGroup(
                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                        .addComponent(getCharsetLabel())
                        .addComponent(getCharsetComboBox()));
        return fieldsPanel;
    }

    public abstract static class AbstractCharsetProcessorUI<
                    T extends Payload, T2 extends AbstractCharsetProcessor<T>>
            implements PayloadProcessorUI<T, T2> {

        private final Charset charset;

        public AbstractCharsetProcessorUI(Charset charset) {
            this.charset = charset;
        }

        public Charset getCharset() {
            return charset;
        }
    }
}
