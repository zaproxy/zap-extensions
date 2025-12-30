/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.addon.llm.ui;

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Objects;
import javax.swing.GroupLayout;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.addon.llm.LlmOptions;
import org.zaproxy.addon.llm.LlmProvider;

@SuppressWarnings("serial")
public class LlmOptionsPanel extends AbstractParamPanel {

    private static final Logger LOGGER = LogManager.getLogger(LlmOptionsPanel.class);

    private static final long serialVersionUID = 1L;

    private JComboBox<LlmProvider> modelProviderComboBox;
    private JTextField apiKeyTextField;
    private JTextField llmendpointTextField;
    private JTextField modelNameTextField;

    public LlmOptionsPanel() {
        super();

        setName(Constant.messages.getString("llm.options.title"));

        JLabel modelProviderLabel =
                new JLabel(Constant.messages.getString("llm.options.label.modelprovider"));
        modelProviderComboBox = new JComboBox<>(LlmProvider.values());

        JLabel llmApiKey = new JLabel(Constant.messages.getString("llm.options.label.apikey"));
        apiKeyTextField = new JPasswordField();

        JLabel llmendpoint = new JLabel(Constant.messages.getString("llm.options.label.endpoint"));
        llmendpointTextField = new JTextField();

        JLabel modelNameLabel =
                new JLabel(Constant.messages.getString("llm.options.label.modelname"));
        modelNameTextField = new JTextField();

        GroupLayout layout = new GroupLayout(this);
        setLayout(layout);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        layout.setHorizontalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                        .addComponent(modelProviderLabel)
                                        .addComponent(llmApiKey)
                                        .addComponent(llmendpoint)
                                        .addComponent(modelNameLabel))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                        .addComponent(modelProviderComboBox)
                                        .addComponent(apiKeyTextField)
                                        .addComponent(llmendpointTextField)
                                        .addComponent(modelNameTextField)));

        layout.setVerticalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(modelProviderLabel)
                                        .addComponent(modelProviderComboBox))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(llmApiKey)
                                        .addComponent(apiKeyTextField))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(llmendpoint)
                                        .addComponent(llmendpointTextField))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(modelNameLabel)
                                        .addComponent(modelNameTextField)));
    }

    @Override
    public String getHelpIndex() {
        return "addon.llm.options";
    }

    @Override
    public void initParam(Object options) {
        LlmOptions llmOptionsParam = ((OptionsParam) options).getParamSet(LlmOptions.class);
        apiKeyTextField.setText(Objects.toString(llmOptionsParam.getApiKey(), ""));
        llmendpointTextField.setText(Objects.toString(llmOptionsParam.getEndpoint(), ""));
        modelNameTextField.setText(Objects.toString(llmOptionsParam.getModelName(), ""));
        modelProviderComboBox.setSelectedItem(llmOptionsParam.getModelProvider());
    }

    @Override
    public void saveParam(Object options) {
        LlmOptions param = ((OptionsParam) options).getParamSet(LlmOptions.class);
        param.setModelProvider((LlmProvider) modelProviderComboBox.getSelectedItem());
        param.setApiKey(apiKeyTextField.getText());
        param.setEndpoint(llmendpointTextField.getText());
        param.setModelName(modelNameTextField.getText());
    }

    @Override
    public void validateParam(Object object) throws Exception {
        String endpoint = llmendpointTextField.getText();
        String apiKey = apiKeyTextField.getText();

        if (StringUtils.isNoneEmpty(apiKey)) {

            java.net.HttpURLConnection connection = null;

            try {
                URL url = new URL(endpoint);
                connection = (HttpURLConnection) url.openConnection();
                connection.setRequestMethod(HttpRequestHeader.GET);
                connection.setConnectTimeout(5000);
                connection.setReadTimeout(5000);
            } catch (Exception e) {
                // Endpoint is not reachable
                LOGGER.error(
                        "Failed to reach the LLM endpoint: HTTP error code: {}", e.getMessage());
                throw new IllegalArgumentException(
                        Constant.messages.getString("llm.options.endpoint.error.unreachable"));
            } finally {
                if (connection != null) {
                    connection.disconnect();
                }
            }
        }
    }
}
