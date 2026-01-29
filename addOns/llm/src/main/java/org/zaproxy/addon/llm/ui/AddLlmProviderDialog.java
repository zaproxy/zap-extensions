/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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

import java.awt.Dialog;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.swing.GroupLayout;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import org.apache.commons.httpclient.URI;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.llm.LlmProvider;
import org.zaproxy.addon.llm.LlmProviderConfig;
import org.zaproxy.zap.view.AbstractFormDialog;

@SuppressWarnings("serial")
public class AddLlmProviderDialog extends AbstractFormDialog {

    private static final Logger LOGGER = LogManager.getLogger(AddLlmProviderDialog.class);

    private static final long serialVersionUID = 1L;

    protected final JPanel fieldsPanel;
    protected final JTextField nameTextField;
    protected final JComboBox<LlmProvider> providerComboBox;
    protected final JPasswordField apiKeyField;
    protected final JTextField endpointField;
    protected final JTextArea modelsArea;

    protected final LlmProviderConfigsTableModel model;

    protected LlmProviderConfig providerConfig;
    protected String originalName;
    private String lastSuggestedName;
    private HttpSender sender;

    public AddLlmProviderDialog(Dialog owner, LlmProviderConfigsTableModel model) {
        super(owner, Constant.messages.getString("llm.options.providers.add.title"), false);

        this.model = model;
        this.sender = new HttpSender(HttpSender.MANUAL_REQUEST_INITIATOR);

        fieldsPanel = new JPanel();

        GroupLayout layout = new GroupLayout(fieldsPanel);
        fieldsPanel.setLayout(layout);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        JLabel nameLabel =
                new JLabel(Constant.messages.getString("llm.options.providers.field.name"));
        nameTextField = new JTextField(30);
        nameLabel.setLabelFor(nameTextField);

        JLabel providerLabel =
                new JLabel(Constant.messages.getString("llm.options.providers.field.provider"));
        providerComboBox =
                new JComboBox<>(
                        Arrays.stream(LlmProvider.values())
                                .filter(provider -> provider != LlmProvider.NONE)
                                .toArray(LlmProvider[]::new));
        providerComboBox.addActionListener(
                e -> {
                    updateEndpointFieldState();
                    updateSuggestedName();
                });
        providerLabel.setLabelFor(providerComboBox);

        JLabel apiKeyLabel =
                new JLabel(Constant.messages.getString("llm.options.providers.field.apikey"));
        apiKeyField = new JPasswordField(30);
        apiKeyLabel.setLabelFor(apiKeyField);

        JLabel endpointLabel =
                new JLabel(Constant.messages.getString("llm.options.providers.field.endpoint"));
        endpointField = new JTextField(30);
        endpointLabel.setLabelFor(endpointField);

        JLabel modelNameLabel =
                new JLabel(Constant.messages.getString("llm.options.providers.field.models"));
        modelsArea = new JTextArea(5, 30);
        modelsArea.setLineWrap(true);
        modelsArea.setWrapStyleWord(true);
        JScrollPane modelsScrollPane = new JScrollPane(modelsArea);
        modelNameLabel.setLabelFor(modelsArea);

        layout.setHorizontalGroup(
                layout.createParallelGroup()
                        .addGroup(
                                layout.createSequentialGroup()
                                        .addGroup(
                                                layout.createParallelGroup(
                                                                GroupLayout.Alignment.TRAILING)
                                                        .addComponent(nameLabel)
                                                        .addComponent(providerLabel)
                                                        .addComponent(apiKeyLabel)
                                                        .addComponent(endpointLabel)
                                                        .addComponent(modelNameLabel))
                                        .addGroup(
                                                layout.createParallelGroup(
                                                                GroupLayout.Alignment.LEADING)
                                                        .addComponent(nameTextField)
                                                        .addComponent(providerComboBox)
                                                        .addComponent(apiKeyField)
                                                        .addComponent(endpointField)
                                                        .addComponent(modelsScrollPane))));

        layout.setVerticalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(nameLabel)
                                        .addComponent(nameTextField))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(providerLabel)
                                        .addComponent(providerComboBox))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(apiKeyLabel)
                                        .addComponent(apiKeyField))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(endpointLabel)
                                        .addComponent(endpointField))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(modelNameLabel)
                                        .addComponent(modelsScrollPane)));

        initView();
        setConfirmButtonEnabled(true);
    }

    @Override
    protected JPanel getFieldsPanel() {
        return fieldsPanel;
    }

    @Override
    protected String getConfirmButtonLabel() {
        return Constant.messages.getString("llm.options.providers.add.button");
    }

    @Override
    protected void init() {
        nameTextField.setText("");
        providerComboBox.setSelectedIndex(0);
        lastSuggestedName = providerComboBox.getSelectedItem().toString();
        apiKeyField.setText("");
        endpointField.setText("");
        modelsArea.setText("");
        providerConfig = null;
        originalName = null;
        updateEndpointFieldState();
        updateSuggestedName();
    }

    @Override
    protected boolean validateFields() {
        String name = StringUtils.trimToEmpty(nameTextField.getText());
        if (name.isEmpty()) {
            View.getSingleton()
                    .showWarningDialog(
                            this,
                            Constant.messages.getString("llm.options.providers.error.name.empty"));
            return false;
        }

        if (isDuplicateName(name)) {
            View.getSingleton()
                    .showWarningDialog(
                            this,
                            Constant.messages.getString(
                                    "llm.options.providers.error.name.duplicate", name));
            return false;
        }

        LlmProvider provider = (LlmProvider) providerComboBox.getSelectedItem();
        if (provider == null) {
            return false;
        }

        String endpoint = StringUtils.trimToEmpty(endpointField.getText());
        if (provider.supportsEndpoint() && !endpoint.isEmpty() && !isEndpointReachable(endpoint)) {
            View.getSingleton()
                    .showWarningDialog(
                            this,
                            Constant.messages.getString("llm.options.endpoint.error.unreachable"));
            return false;
        }

        return true;
    }

    @Override
    protected void performAction() {
        LlmProvider provider = (LlmProvider) providerComboBox.getSelectedItem();
        String endpoint = StringUtils.trimToEmpty(endpointField.getText());
        if (provider != null && !provider.supportsEndpoint()) {
            endpoint = "";
        }

        providerConfig =
                new LlmProviderConfig(
                        StringUtils.trimToEmpty(nameTextField.getText()),
                        provider,
                        new String(apiKeyField.getPassword()),
                        endpoint,
                        parseModels());
    }

    public LlmProviderConfig getProviderConfig() {
        LlmProviderConfig config = providerConfig;
        providerConfig = null;
        return config;
    }

    protected void updateEndpointFieldState() {
        LlmProvider provider = (LlmProvider) providerComboBox.getSelectedItem();
        endpointField.setEnabled(provider == null || provider.supportsEndpoint());
    }

    protected void updateSuggestedName() {
        LlmProvider provider = (LlmProvider) providerComboBox.getSelectedItem();
        if (provider == null) {
            return;
        }
        String currentName = StringUtils.trimToEmpty(nameTextField.getText());
        if (currentName.isEmpty() || currentName.equals(lastSuggestedName)) {
            lastSuggestedName = provider.toString();
            nameTextField.setText(lastSuggestedName);
        }
    }

    protected boolean isDuplicateName(String name) {
        for (LlmProviderConfig config : model.getElements()) {
            if (name.equals(config.getName()) && !name.equals(originalName)) {
                return true;
            }
        }
        return false;
    }

    private boolean isEndpointReachable(String endpoint) {
        try {
            sender.sendAndReceive(new HttpMessage(new URI(endpoint, true)));
        } catch (Exception e) {
            LOGGER.warn("Failed to reach the LLM endpoint: {}", e.getMessage());
            return false;
        }
        return true;
    }

    private List<String> parseModels() {
        List<String> models = new ArrayList<>();
        for (String line : modelsArea.getText().split("\\R")) {
            String trimmed = StringUtils.trimToEmpty(line);
            if (!trimmed.isEmpty()) {
                models.add(trimmed);
            }
        }
        return models;
    }
}
