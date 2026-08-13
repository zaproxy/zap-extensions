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

import java.awt.Component;
import java.awt.Dialog;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import javax.swing.DefaultComboBoxModel;
import javax.swing.GroupLayout;
import javax.swing.JCheckBox;
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
import org.jdesktop.swingx.JXComboBox;
import org.jdesktop.swingx.decorator.AbstractHighlighter;
import org.jdesktop.swingx.decorator.ComponentAdapter;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.llm.LlmProvider;
import org.zaproxy.addon.llm.LlmProvider.SuggestedEndpoint;
import org.zaproxy.addon.llm.LlmProviderConfig;
import org.zaproxy.zap.utils.ZapNumberSpinner;
import org.zaproxy.zap.view.AbstractFormDialog;

@SuppressWarnings("serial")
public class AddLlmProviderDialog extends AbstractFormDialog {

    private static final Logger LOGGER = LogManager.getLogger(AddLlmProviderDialog.class);

    private static final long serialVersionUID = 1L;

    protected final JPanel fieldsPanel;
    protected final JTextField nameTextField;
    protected final JComboBox<LlmProvider> providerComboBox;
    protected final JPasswordField apiKeyField;
    protected final JComboBox<SuggestedEndpoint> endpointComboBox;
    protected final JTextArea modelsArea;
    protected final ZapNumberSpinner timeoutSpinner;
    protected final JCheckBox trustedCheckBox;

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
                    updateSuggestedEndpoint();
                    updateSuggestedTrusted();
                });
        providerLabel.setLabelFor(providerComboBox);

        JLabel apiKeyLabel =
                new JLabel(Constant.messages.getString("llm.options.providers.field.apikey"));
        apiKeyField = new JPasswordField(30);
        apiKeyLabel.setLabelFor(apiKeyField);

        JLabel endpointLabel =
                new JLabel(Constant.messages.getString("llm.options.providers.field.endpoint"));
        JXComboBox endpointCombo = new JXComboBox();
        endpointCombo.setEditable(true);
        endpointCombo.addHighlighter(
                new AbstractHighlighter() {
                    @Override
                    protected Component doHighlight(Component component, ComponentAdapter adapter) {
                        if (component instanceof JLabel label
                                && adapter.getValue() instanceof SuggestedEndpoint suggested) {
                            label.setText(suggested.getLabel());
                        }
                        return component;
                    }
                });
        @SuppressWarnings("unchecked")
        JComboBox<SuggestedEndpoint> typedEndpointCombo = endpointCombo;
        endpointComboBox = typedEndpointCombo;
        endpointLabel.setLabelFor(endpointComboBox);

        JLabel modelNameLabel =
                new JLabel(Constant.messages.getString("llm.options.providers.field.models"));
        modelsArea = new JTextArea(5, 30);
        modelsArea.setLineWrap(true);
        modelsArea.setWrapStyleWord(true);
        JScrollPane modelsScrollPane = new JScrollPane(modelsArea);
        modelNameLabel.setLabelFor(modelsArea);

        JLabel timeoutLabel =
                new JLabel(Constant.messages.getString("llm.options.providers.field.timeout"));
        timeoutSpinner =
                new ZapNumberSpinner(
                        1, LlmProviderConfig.DEFAULT_TIMEOUT_SECONDS, Integer.MAX_VALUE);
        timeoutLabel.setLabelFor(timeoutSpinner);

        trustedCheckBox =
                new JCheckBox(Constant.messages.getString("llm.options.providers.field.trusted"));

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
                                                        .addComponent(modelNameLabel)
                                                        .addComponent(timeoutLabel))
                                        .addGroup(
                                                layout.createParallelGroup(
                                                                GroupLayout.Alignment.LEADING)
                                                        .addComponent(nameTextField)
                                                        .addComponent(providerComboBox)
                                                        .addComponent(apiKeyField)
                                                        .addComponent(endpointComboBox)
                                                        .addComponent(modelsScrollPane)
                                                        .addComponent(timeoutSpinner)
                                                        .addComponent(trustedCheckBox))));

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
                                        .addComponent(endpointComboBox))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(modelNameLabel)
                                        .addComponent(modelsScrollPane))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(timeoutLabel)
                                        .addComponent(timeoutSpinner))
                        .addComponent(trustedCheckBox));

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
        setEndpointText("");
        modelsArea.setText("");
        timeoutSpinner.setValue(LlmProviderConfig.DEFAULT_TIMEOUT_SECONDS);
        providerConfig = null;
        originalName = null;
        updateEndpointFieldState();
        updateSuggestedName();
        updateSuggestedEndpoint();
        updateSuggestedTrusted();
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

        String endpoint = getEndpointText();
        if (provider.isEndpointRequired() && endpoint.isEmpty()) {
            View.getSingleton()
                    .showWarningDialog(
                            this,
                            Constant.messages.getString(
                                    "llm.options.providers.error.endpoint.empty"));
            return false;
        }
        if (provider.isModelRequired() && parseModels().isEmpty()) {
            View.getSingleton()
                    .showWarningDialog(
                            this,
                            Constant.messages.getString("llm.options.providers.error.model.empty"));
            return false;
        }
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
        String endpoint = getEndpointText();
        if (provider != null && !provider.supportsEndpoint()) {
            endpoint = "";
        }

        providerConfig =
                new LlmProviderConfig(
                        StringUtils.trimToEmpty(nameTextField.getText()),
                        provider,
                        new String(apiKeyField.getPassword()),
                        endpoint,
                        parseModels(),
                        trustedCheckBox.isSelected(),
                        timeoutSpinner.getValue());
    }

    public LlmProviderConfig getProviderConfig() {
        LlmProviderConfig config = providerConfig;
        providerConfig = null;
        return config;
    }

    protected void updateEndpointFieldState() {
        LlmProvider provider = (LlmProvider) providerComboBox.getSelectedItem();
        endpointComboBox.setEnabled(provider == null || provider.supportsEndpoint());
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

    protected void updateSuggestedEndpoint() {
        LlmProvider provider = (LlmProvider) providerComboBox.getSelectedItem();
        if (provider == null) {
            return;
        }

        String currentEndpoint = getEndpointText();
        endpointComboBox.setModel(
                new DefaultComboBoxModel<>(
                        provider.getSuggestedEndpoints().toArray(SuggestedEndpoint[]::new)));

        if (!provider.supportsEndpoint()) {
            setEndpointText("");
            return;
        }

        String nextEndpoint = currentEndpoint;
        String suggestedEndpoint = endpointValueOnSelect(provider);
        if (currentEndpoint.isEmpty()
                || (isSuggestedEndpoint(currentEndpoint)
                        && !currentEndpoint.equals(suggestedEndpoint))) {
            nextEndpoint = suggestedEndpoint;
        }
        setEndpointText(nextEndpoint);
    }

    protected void updateSuggestedTrusted() {
        LlmProvider provider = (LlmProvider) providerComboBox.getSelectedItem();
        if (provider != null) {
            trustedCheckBox.setSelected(provider.isTrustedByDefault());
        }
    }

    static String endpointValueOnSelect(LlmProvider provider) {
        if (provider == null || !provider.supportsEndpoint()) {
            return "";
        }
        List<SuggestedEndpoint> suggested = provider.getSuggestedEndpoints();
        return suggested.size() == 1 ? suggested.get(0).url() : "";
    }

    private static boolean isSuggestedEndpoint(String endpoint) {
        return Stream.of(LlmProvider.values())
                .flatMap(provider -> provider.getSuggestedEndpoints().stream())
                .anyMatch(suggested -> suggested.url().equals(endpoint));
    }

    protected String getEndpointText() {
        Object item = endpointComboBox.getSelectedItem();
        return item == null ? "" : StringUtils.trimToEmpty(item.toString());
    }

    protected void setEndpointText(String endpoint) {
        String url = StringUtils.defaultString(endpoint);
        for (int i = 0; i < endpointComboBox.getItemCount(); i++) {
            SuggestedEndpoint suggested = endpointComboBox.getItemAt(i);
            if (suggested.url().equals(url)) {
                endpointComboBox.setSelectedIndex(i);
                return;
            }
        }
        endpointComboBox.setSelectedItem(url);
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
