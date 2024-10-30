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
package org.zaproxy.addon.llm.ui.settings;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.addon.llm.utils.Requestor;

import javax.swing.JTextField;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPasswordField;
import javax.swing.GroupLayout;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Objects;


public class LlmOptionsPanel extends AbstractParamPanel {

    private static final Logger LOGGER = LogManager.getLogger(LlmOptionsPanel.class);


    private static final long serialVersionUID = -2690686914494943483L;

    private JTextField apiKeyTextField;
    private JTextField llmendpointTextField;

    private JComboBox<String> llmModelsComboBox;  // Added JComboBox for LLM models

    public LlmOptionsPanel() {
        super();
        this.initComponents();
    }

    private void initComponents() {
        super.setName(Constant.messages.getString("llm.options.title"));

        JLabel llmApiKey = new JLabel(Constant.messages.getString("llm.options.label.apikey"));
        this.apiKeyTextField = new JPasswordField();  // Initialize as JPasswordField

        JLabel llmendpoint = new JLabel(Constant.messages.getString("llm.options.label.endpoint"));
        this.llmendpointTextField = new JTextField();  // Initialize as JPasswordField

        JLabel llmModelsLabel = new JLabel("Select LLM Model:");  // Label for the combo box
        this.llmModelsComboBox = new JComboBox<>(new String[]{"gpt-4o"});  //

        GroupLayout layout = new GroupLayout(this);
        super.setLayout(layout);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        layout.setHorizontalGroup(
                layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                        .addGroup(layout.createSequentialGroup()
                                .addComponent(llmApiKey)
                                .addComponent(this.apiKeyTextField))
                        .addGroup(layout.createSequentialGroup()
                                .addComponent(llmendpoint)
                                .addComponent(this.llmendpointTextField))
                        .addGroup(layout.createSequentialGroup()  // Add horizontal group for combo box
                                .addComponent(llmModelsLabel)
                                .addComponent(this.llmModelsComboBox)));

        layout.setVerticalGroup(
                layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(llmApiKey)
                                .addComponent(this.apiKeyTextField))
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(llmendpoint)
                                .addComponent(this.llmendpointTextField))
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)  // Add vertical group for combo box
                                .addComponent(llmModelsLabel)
                                .addComponent(this.llmModelsComboBox)));
    }

    @Override
    public String getHelpIndex() {
        return "llm.options";
    }

    @Override
    public void initParam(Object object) {
        final LlmOptionsParam llmOptionsParam =
                ((OptionsParam) object).getParamSet(LlmOptionsParam.class);
        this.apiKeyTextField.setText(Objects.toString(llmOptionsParam.getApiKey(), ""));
        this.llmendpointTextField.setText(Objects.toString(llmOptionsParam.getEndpoint(), ""));
        // this.llmModelsComboBox : already selected value
    }

    @Override
    public void saveParam(Object object) {
        final OptionsParam options = (OptionsParam) object;
        final LlmOptionsParam param = options.getParamSet(LlmOptionsParam.class);
        param.setApiKey(this.apiKeyTextField.getText());
        param.setEndpoint(this.llmendpointTextField.getText());
        param.setModelName(this.llmModelsComboBox.getSelectedItem().toString());
    }

    @Override
    public void validateParam(Object object) throws Exception {
        String endpoint = this.llmendpointTextField.getText();
        java.net.HttpURLConnection connection = null;

        try {
            URL url = new URL(endpoint);
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(5000); // Set timeout as per your need
            connection.setReadTimeout(5000); // Set timeout as per your need
            int responseCode = connection.getResponseCode();
        } catch (Exception e) {
            // Endpoint is not reachable
            LOGGER.error("Failed to reach the LLM endpoint : HTTP error code : " + e.getMessage());
            throw new IllegalArgumentException(
                    Constant.messages.getString("llm.options.endpoint.error.unreachable"));
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }

    }
}
