/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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

import com.google.gson.JsonParser;
import java.text.MessageFormat;
import javax.swing.GroupLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;
import org.zaproxy.zap.extension.fuzz.payloads.generator.JsonPayloadGenerator;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUI;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUIHandler;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUIPanel;
import org.zaproxy.zap.model.MessageLocation;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.utils.ZapNumberSpinner;
import org.zaproxy.zap.utils.ZapTextArea;

public class JsonPayloadGeneratorAdapterUIHandler
        implements PayloadGeneratorUIHandler<
                DefaultPayload,
                JsonPayloadGenerator,
                JsonPayloadGeneratorAdapterUIHandler.JsonPayloadGeneratorUI> {

    private static final String PAYLOAD_GENERATOR_NAME = getString("name");
    private static final String PAYLOAD_GENERATOR_DESC = getString("description");

    @Override
    public String getName() {
        return PAYLOAD_GENERATOR_NAME;
    }

    @Override
    public Class<JsonPayloadGeneratorUI> getPayloadGeneratorUIClass() {
        return JsonPayloadGeneratorUI.class;
    }

    @Override
    public Class<
                    ? extends
                            PayloadGeneratorUIPanel<
                                    DefaultPayload, JsonPayloadGenerator, JsonPayloadGeneratorUI>>
            getPayloadGeneratorUIPanelClass() {
        return JsonPayloadGeneratorUIPanel.class;
    }

    @Override
    public PayloadGeneratorUIPanel<DefaultPayload, JsonPayloadGenerator, JsonPayloadGeneratorUI>
            createPanel() {
        return new JsonPayloadGeneratorUIPanel();
    }

    public static class JsonPayloadGeneratorUI
            implements PayloadGeneratorUI<DefaultPayload, JsonPayloadGenerator> {
        private final JsonPayloadGenerator jsonPayloadGenerator;

        public JsonPayloadGeneratorUI(JsonPayloadGenerator generator) {
            this.jsonPayloadGenerator = generator;
        }

        @Override
        public Class<? extends JsonPayloadGenerator> getPayloadGeneratorClass() {
            return JsonPayloadGenerator.class;
        }

        @Override
        public String getName() {
            return PAYLOAD_GENERATOR_NAME;
        }

        @Override
        public String getDescription() {

            return MessageFormat.format(PAYLOAD_GENERATOR_DESC, jsonPayloadGenerator.getJson());
        }

        @Override
        public long getNumberOfPayloads() {
            return jsonPayloadGenerator.getNumberOfPayloads();
        }

        @Override
        public JsonPayloadGenerator getPayloadGenerator() {
            return jsonPayloadGenerator;
        }

        @Override
        public PayloadGeneratorUI<DefaultPayload, JsonPayloadGenerator> copy() {
            return this;
        }
    }

    public static class JsonPayloadGeneratorUIPanel
            extends AbstractPersistentPayloadGeneratorUIPanel<
                    DefaultPayload, JsonPayloadGenerator, JsonPayloadGeneratorUI> {
        private static final String JSON_FIELD_LABEL = getString("original.field.label");
        private static final String NUMBER_PAYLOADS_LABEL = getString("number.payloads.label");

        private JPanel fieldsPanel;
        private ZapTextArea jsonTextArea;
        private ZapNumberSpinner numberOfPayloadsSpinner;

        private JsonPayloadGeneratorUI oldGenerator;

        public JsonPayloadGeneratorUIPanel() {
            fieldsPanel = new JPanel();

            GroupLayout layout = new GroupLayout(fieldsPanel);
            fieldsPanel.setLayout(layout);
            layout.setAutoCreateGaps(true);

            numberOfPayloadsSpinner = new ZapNumberSpinner(1, 1, Integer.MAX_VALUE);
            JLabel numberOfPayloadsLabel = new JLabel(NUMBER_PAYLOADS_LABEL);
            numberOfPayloadsLabel.setLabelFor(numberOfPayloadsSpinner);

            JLabel jsonFieldLabel = new JLabel(JSON_FIELD_LABEL);
            jsonFieldLabel.setLabelFor(getJsonTextArea());
            JScrollPane jsonFieldScrollPane = new JScrollPane(getJsonTextArea());

            layout.setHorizontalGroup(
                    layout.createSequentialGroup()
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                            .addComponent(numberOfPayloadsLabel)
                                            .addComponent(jsonFieldLabel))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                            .addComponent(numberOfPayloadsSpinner)
                                            .addComponent(jsonFieldScrollPane)));

            layout.setVerticalGroup(
                    layout.createSequentialGroup()
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(numberOfPayloadsLabel)
                                            .addComponent(numberOfPayloadsSpinner))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(jsonFieldLabel)
                                            .addComponent(jsonFieldScrollPane)));
        }

        @Override
        protected JsonPayloadGenerator getPayloadGenerator() {
            if (!validate()) {
                return null;
            }
            return new JsonPayloadGenerator(
                    jsonTextArea.getText(), numberOfPayloadsSpinner.getValue());
        }

        @Override
        public void init(MessageLocation messageLocation) {
            getJsonTextArea().setText(messageLocation.getValue());
        }

        @Override
        public JPanel getComponent() {
            return fieldsPanel;
        }

        @Override
        public void setPayloadGeneratorUI(JsonPayloadGeneratorUI payloadGeneratorUI) {
            oldGenerator = payloadGeneratorUI;
            numberOfPayloadsSpinner.setValue(
                    payloadGeneratorUI.getPayloadGenerator().getNumberOfPayloads());
            jsonTextArea.setText(payloadGeneratorUI.getPayloadGenerator().getJson());
            jsonTextArea.discardAllEdits();
        }

        @Override
        public JsonPayloadGeneratorUI getPayloadGeneratorUI() {
            if (oldGenerator != null) {
                return oldGenerator;
            }

            return new JsonPayloadGeneratorUI(getPayloadGenerator());
        }

        @Override
        public void clear() {
            oldGenerator = null;

            getJsonTextArea().setText("");
            jsonTextArea.discardAllEdits();
            numberOfPayloadsSpinner.setValue(1);
        }

        @Override
        public boolean validate() {
            if (oldGenerator != null
                    && getJsonTextArea()
                            .getText()
                            .equals(oldGenerator.getPayloadGenerator().getJson())
                    && numberOfPayloadsSpinner.getValue()
                            == oldGenerator.getPayloadGenerator().getNumberOfPayloads()) {
                return true;
            }

            if (getJsonTextArea().getDocument().getLength() == 0) {
                return false;
            }
            if (isInvalidJson(getJsonTextArea().getText())) {
                return false;
            }

            oldGenerator = null;
            return true;
        }

        private boolean isInvalidJson(String json) {
            try {
                new JsonParser().parse(json);
                return false;
            } catch (Exception e) {
                return true;
            }
        }

        private ZapTextArea getJsonTextArea() {
            if (jsonTextArea == null) {
                jsonTextArea = new ZapTextArea();
                jsonTextArea.setColumns(25);
                jsonTextArea.setRows(10);
                jsonTextArea.setFont(FontUtils.getFont("Monospaced"));
            }
            return jsonTextArea;
        }
    }

    private static String getString(String suffix) {
        return Constant.messages.getString("fuzz.payloads.generator.json." + suffix);
    }
}
