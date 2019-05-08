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
package org.zaproxy.zap.extension.fuzz.httpfuzzer.processors;

import java.util.List;
import javax.swing.GroupLayout;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.anticsrf.AntiCsrfToken;
import org.zaproxy.zap.extension.anticsrf.ExtensionAntiCSRF;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.AbstractHttpFuzzerMessageProcessorUIPanel;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerMessageProcessorUI;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerMessageProcessorUIHandler;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.processors.AntiCsrfHttpFuzzerMessageProcessorUIHandler.AntiCsrfHttpFuzzerMessageProcessorUI;

public class AntiCsrfHttpFuzzerMessageProcessorUIHandler
        implements HttpFuzzerMessageProcessorUIHandler<
                AntiCsrfHttpFuzzerMessageProcessor, AntiCsrfHttpFuzzerMessageProcessorUI> {

    private static final String PROCESSOR_NAME =
            Constant.messages.getString("fuzz.httpfuzzer.processor.acsrffuzz.name");

    private final ExtensionAntiCSRF extensionAntiCSRF;
    private HttpMessage message;

    public AntiCsrfHttpFuzzerMessageProcessorUIHandler(ExtensionAntiCSRF extensionAntiCSRF) {
        this.extensionAntiCSRF = extensionAntiCSRF;
    }

    @Override
    public boolean isEnabled(HttpMessage message) {
        List<AntiCsrfToken> tokens = extensionAntiCSRF.getTokens(message);
        if (tokens != null && !tokens.isEmpty()) {
            this.message = message;
            return true;
        }
        return false;
    }

    @Override
    public boolean isDefault() {
        return true;
    }

    @Override
    public HttpFuzzerMessageProcessorUI<AntiCsrfHttpFuzzerMessageProcessor> createDefault() {
        if (message == null) {
            return null;
        }

        AntiCsrfHttpFuzzerMessageProcessorUI processor =
                new AntiCsrfHttpFuzzerMessageProcessorUI(
                        extensionAntiCSRF, extensionAntiCSRF.getTokens(message).get(0), false);
        message = null;
        return processor;
    }

    @Override
    public String getName() {
        return PROCESSOR_NAME;
    }

    @Override
    public Class<HttpMessage> getMessageType() {
        return HttpMessage.class;
    }

    @Override
    public Class<AntiCsrfHttpFuzzerMessageProcessor> getFuzzerMessageProcessorType() {
        return AntiCsrfHttpFuzzerMessageProcessor.class;
    }

    @Override
    public Class<AntiCsrfHttpFuzzerMessageProcessorUI> getFuzzerMessageProcessorUIType() {
        return AntiCsrfHttpFuzzerMessageProcessorUI.class;
    }

    @Override
    public AntiCsrfHttpFuzzerMessageProcessorUIPanel createPanel() {
        return new AntiCsrfHttpFuzzerMessageProcessorUIPanel(extensionAntiCSRF);
    }

    public static class AntiCsrfHttpFuzzerMessageProcessorUI
            implements HttpFuzzerMessageProcessorUI<AntiCsrfHttpFuzzerMessageProcessor> {

        private final ExtensionAntiCSRF extensionAntiCSRF;
        private final AntiCsrfToken antiCsrfToken;
        private final boolean showTokenRequests;

        public AntiCsrfHttpFuzzerMessageProcessorUI(
                ExtensionAntiCSRF extensionAntiCSRF,
                AntiCsrfToken antiCsrfToken,
                boolean showTokenRequests) {
            this.extensionAntiCSRF = extensionAntiCSRF;
            this.antiCsrfToken = antiCsrfToken;
            this.showTokenRequests = showTokenRequests;
        }

        public AntiCsrfToken getAntiCsrfToken() {
            return antiCsrfToken;
        }

        public boolean isShowTokenRequests() {
            return showTokenRequests;
        }

        @Override
        public boolean isMutable() {
            return true;
        }

        @Override
        public String getName() {
            return PROCESSOR_NAME;
        }

        @Override
        public String getDescription() {
            return Constant.messages.getString(
                    "fuzz.httpfuzzer.processor.acsrffuzz.description", antiCsrfToken.getName());
        }

        @Override
        public AntiCsrfHttpFuzzerMessageProcessor getFuzzerMessageProcessor() {
            return new AntiCsrfHttpFuzzerMessageProcessor(
                    extensionAntiCSRF, antiCsrfToken, showTokenRequests);
        }

        @Override
        public AntiCsrfHttpFuzzerMessageProcessorUI copy() {
            return this;
        }
    }

    public static class AntiCsrfHttpFuzzerMessageProcessorUIPanel
            extends AbstractHttpFuzzerMessageProcessorUIPanel<
                    AntiCsrfHttpFuzzerMessageProcessor, AntiCsrfHttpFuzzerMessageProcessorUI> {

        private static final String NAME_FIELD_LABEL =
                Constant.messages.getString("fuzz.httpfuzzer.processor.acsrffuzz.panel.label.name");
        private static final String SOURCE_FIELD_LABEL =
                Constant.messages.getString(
                        "fuzz.httpfuzzer.processor.acsrffuzz.panel.label.source");
        private static final String TARGET_FIELD_LABEL =
                Constant.messages.getString(
                        "fuzz.httpfuzzer.processor.acsrffuzz.panel.label.target");
        private static final String PREVIOUS_VALUE_FIELD_LABEL =
                Constant.messages.getString("fuzz.httpfuzzer.processor.acsrffuzz.panel.label.prev");
        private static final String SHOW_TOKENS_FIELD_LABEL =
                Constant.messages.getString(
                        "fuzz.httpfuzzer.processor.acsrffuzz.panel.label.showtokens");

        private final ExtensionAntiCSRF extensionAntiCSRF;

        private final JTextField nameValueLabel;
        private final JTextField previousValueLabel;
        private final JTextField sourceUrlLabel;
        private final JTextField targetUrlLabel;
        private final JCheckBox showTokensCheckBox;

        private final JPanel fieldsPanel;

        private AntiCsrfToken antiCsrfToken;

        public AntiCsrfHttpFuzzerMessageProcessorUIPanel(ExtensionAntiCSRF extensionAntiCSRF) {
            this.extensionAntiCSRF = extensionAntiCSRF;

            fieldsPanel = new JPanel();

            GroupLayout layout = new GroupLayout(fieldsPanel);
            fieldsPanel.setLayout(layout);
            layout.setAutoCreateGaps(true);

            JLabel nameLabel = new JLabel(NAME_FIELD_LABEL);
            nameValueLabel = new JTextField();
            nameValueLabel.setEditable(false);

            JLabel sourceLabel = new JLabel(SOURCE_FIELD_LABEL);
            sourceUrlLabel = new JTextField();
            sourceUrlLabel.setEditable(false);

            JLabel targetLabel = new JLabel(TARGET_FIELD_LABEL);
            targetUrlLabel = new JTextField();
            targetUrlLabel.setEditable(false);
            targetUrlLabel.setColumns(25);

            JLabel previousLabel = new JLabel(PREVIOUS_VALUE_FIELD_LABEL);
            previousValueLabel = new JTextField();
            previousValueLabel.setEditable(false);

            showTokensCheckBox = new JCheckBox();
            JLabel showTokensLabel = new JLabel(SHOW_TOKENS_FIELD_LABEL);
            showTokensLabel.setLabelFor(showTokensCheckBox);

            layout.setHorizontalGroup(
                    layout.createSequentialGroup()
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                            .addComponent(nameLabel)
                                            .addComponent(sourceLabel)
                                            .addComponent(targetLabel)
                                            .addComponent(previousLabel)
                                            .addComponent(showTokensLabel))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                            .addComponent(nameValueLabel)
                                            .addComponent(sourceUrlLabel)
                                            .addComponent(targetUrlLabel)
                                            .addComponent(previousValueLabel)
                                            .addComponent(showTokensCheckBox)));

            layout.setVerticalGroup(
                    layout.createSequentialGroup()
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(nameLabel)
                                            .addComponent(nameValueLabel))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(sourceLabel)
                                            .addComponent(sourceUrlLabel))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(targetLabel)
                                            .addComponent(targetUrlLabel))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(previousLabel)
                                            .addComponent(previousValueLabel))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(showTokensLabel)
                                            .addComponent(showTokensCheckBox)));
        }

        @Override
        public void init(HttpMessage message) {
            antiCsrfToken = extensionAntiCSRF.getTokens(message).get(0);
            updateTokenFields();

            fieldsPanel.revalidate();
            fieldsPanel.repaint();
        }

        private void updateTokenFields() {
            nameValueLabel.setText(antiCsrfToken.getName());
            sourceUrlLabel.setText(antiCsrfToken.getMsg().getRequestHeader().getURI().toString());
            targetUrlLabel.setText(antiCsrfToken.getTargetURL());
            previousValueLabel.setText(antiCsrfToken.getValue());
        }

        @Override
        public void clear() {
            antiCsrfToken = null;
            nameValueLabel.setText("");
            sourceUrlLabel.setText("");
            targetUrlLabel.setText("");
            previousValueLabel.setText("");
            showTokensCheckBox.setSelected(false);
        }

        @Override
        public JPanel getComponent() {
            return fieldsPanel;
        }

        @Override
        public void setFuzzerMessageProcessorUI(
                AntiCsrfHttpFuzzerMessageProcessorUI messageProcessorUI) {
            antiCsrfToken = messageProcessorUI.getAntiCsrfToken();
            updateTokenFields();

            showTokensCheckBox.setSelected(messageProcessorUI.isShowTokenRequests());
        }

        @Override
        public AntiCsrfHttpFuzzerMessageProcessorUI getFuzzerMessageProcessorUI() {
            return new AntiCsrfHttpFuzzerMessageProcessorUI(
                    extensionAntiCSRF, antiCsrfToken, showTokensCheckBox.isSelected());
        }
    }
}
