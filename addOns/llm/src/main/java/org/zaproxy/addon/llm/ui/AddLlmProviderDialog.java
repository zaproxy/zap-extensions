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

import java.awt.CardLayout;
import java.awt.Component;
import java.awt.Dialog;
import java.awt.Dimension;
import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import javax.swing.DefaultComboBoxModel;
import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import org.apache.commons.httpclient.URI;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jdesktop.swingx.JXComboBox;
import org.jdesktop.swingx.decorator.AbstractHighlighter;
import org.jdesktop.swingx.decorator.ComponentAdapter;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.llm.ExtensionLlm;
import org.zaproxy.addon.llm.LlmLocalModelDownloadUi;
import org.zaproxy.addon.llm.LlmProvider;
import org.zaproxy.addon.llm.LlmProvider.SuggestedEndpoint;
import org.zaproxy.addon.llm.LlmProviderConfig;
import org.zaproxy.addon.llm.LocalLlmModelPath;
import org.zaproxy.zap.utils.ZapNumberSpinner;
import org.zaproxy.zap.view.AbstractFormDialog;

@SuppressWarnings("serial")
public class AddLlmProviderDialog extends AbstractFormDialog {

    private static final Logger LOGGER = LogManager.getLogger(AddLlmProviderDialog.class);

    private static final long serialVersionUID = 1L;

    private static final String CARD_REMOTE = "remote";
    private static final String CARD_LOCAL = "local";

    protected final JPanel fieldsPanel;
    protected final JTextField nameTextField;
    protected final JComboBox<LlmProvider> providerComboBox;
    protected final JPasswordField apiKeyField;
    protected final JComboBox<SuggestedEndpoint> endpointComboBox;
    protected final JTextArea modelsArea;
    protected final ZapNumberSpinner timeoutSpinner;
    protected final JCheckBox trustedCheckBox;
    protected final DefaultTableModel localModelsTableModel;
    protected final JTable localModelsTable;
    protected final JLabel modelNameLabel;
    protected final JButton browseModelButton;
    protected final JButton downloadModelButton;
    protected final JButton removeModelButton;
    protected final JPanel modelsPanel;
    private final CardLayout modelsCardLayout;
    private final JPanel modelsCardsPanel;

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
        providerComboBox = new JComboBox<>(availableProviders(null));
        providerComboBox.addActionListener(
                e -> {
                    updateEndpointFieldState();
                    updateApiKeyFieldState();
                    updateModelsFieldState();
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

        modelNameLabel =
                new JLabel(Constant.messages.getString("llm.options.providers.field.models"));

        modelsArea = new JTextArea(5, 30);
        modelsArea.setLineWrap(true);
        modelsArea.setWrapStyleWord(true);
        JScrollPane remoteModelsScrollPane = new JScrollPane(modelsArea);

        localModelsTableModel =
                new DefaultTableModel(
                        new Object[] {
                            Constant.messages.getString("llm.options.providers.field.models.table")
                        },
                        0) {
                    private static final long serialVersionUID = 1L;

                    @Override
                    public boolean isCellEditable(int row, int column) {
                        return false;
                    }
                };
        localModelsTable = new JTable(localModelsTableModel);
        localModelsTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        localModelsTable.setPreferredScrollableViewportSize(new Dimension(300, 80));
        localModelsTable
                .getColumnModel()
                .getColumn(0)
                .setCellRenderer(
                        new DefaultTableCellRenderer() {
                            private static final long serialVersionUID = 1L;

                            @Override
                            public Component getTableCellRendererComponent(
                                    JTable table,
                                    Object value,
                                    boolean isSelected,
                                    boolean hasFocus,
                                    int row,
                                    int column) {
                                Component component =
                                        super.getTableCellRendererComponent(
                                                table, value, isSelected, hasFocus, row, column);
                                if (value == null) {
                                    setToolTipText(null);
                                    return component;
                                }
                                String stored = value.toString();
                                setText(LocalLlmModelPath.toDisplayName(stored));
                                setToolTipText(LocalLlmModelPath.toStoredModelId(stored));
                                return component;
                            }
                        });
        JScrollPane localModelsScrollPane = new JScrollPane(localModelsTable);

        browseModelButton =
                new JButton(
                        Constant.messages.getString("llm.options.providers.field.model.browse"));
        browseModelButton.addActionListener(e -> browseForModelPath());

        downloadModelButton =
                new JButton(
                        Constant.messages.getString("llm.options.providers.field.model.download"));
        downloadModelButton.addActionListener(e -> downloadModel());

        removeModelButton =
                new JButton(
                        Constant.messages.getString("llm.options.providers.field.model.remove"));
        removeModelButton.addActionListener(e -> removeSelectedLocalModels());

        JPanel localModelsPanel = new JPanel();
        GroupLayout localLayout = new GroupLayout(localModelsPanel);
        localModelsPanel.setLayout(localLayout);
        localLayout.setAutoCreateGaps(true);
        localLayout.setHorizontalGroup(
                localLayout
                        .createSequentialGroup()
                        .addComponent(localModelsScrollPane)
                        .addGroup(
                                localLayout
                                        .createParallelGroup()
                                        .addComponent(downloadModelButton)
                                        .addComponent(browseModelButton)
                                        .addComponent(removeModelButton)));
        localLayout.setVerticalGroup(
                localLayout
                        .createParallelGroup(GroupLayout.Alignment.LEADING)
                        .addComponent(localModelsScrollPane)
                        .addGroup(
                                localLayout
                                        .createSequentialGroup()
                                        .addComponent(downloadModelButton)
                                        .addComponent(browseModelButton)
                                        .addComponent(removeModelButton)));

        modelsCardLayout = new CardLayout();
        modelsCardsPanel = new JPanel(modelsCardLayout);
        modelsCardsPanel.add(remoteModelsScrollPane, CARD_REMOTE);
        modelsCardsPanel.add(localModelsPanel, CARD_LOCAL);

        modelsPanel = modelsCardsPanel;
        modelNameLabel.setLabelFor(modelsPanel);

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
                                                        .addComponent(modelsPanel)
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
                                layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                        .addComponent(modelNameLabel)
                                        .addComponent(modelsPanel))
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
        refreshProviders(null);
        nameTextField.setText("");
        providerComboBox.setSelectedIndex(0);
        lastSuggestedName = providerComboBox.getSelectedItem().toString();
        apiKeyField.setText("");
        setEndpointText("");
        setModels(List.of());
        timeoutSpinner.setValue(LlmProviderConfig.DEFAULT_TIMEOUT_SECONDS);
        providerConfig = null;
        originalName = null;
        updateEndpointFieldState();
        updateApiKeyFieldState();
        updateModelsFieldState();
        updateSuggestedName();
        updateSuggestedEndpoint();
        updateSuggestedTrusted();
    }

    protected void setModels(List<String> models) {
        modelsArea.setText(String.join("\n", models));
        localModelsTableModel.setRowCount(0);
        for (String modelId : models) {
            if (StringUtils.isNotBlank(modelId)) {
                localModelsTableModel.addRow(
                        new Object[] {LocalLlmModelPath.toStoredModelId(modelId)});
            }
        }
    }

    protected void refreshProviders(LlmProvider alwaysInclude) {
        LlmProvider selected = (LlmProvider) providerComboBox.getSelectedItem();
        providerComboBox.removeAllItems();
        for (LlmProvider provider : availableProviders(alwaysInclude)) {
            providerComboBox.addItem(provider);
        }
        if (selected != null) {
            providerComboBox.setSelectedItem(selected);
        }
        if (providerComboBox.getSelectedItem() == null && providerComboBox.getItemCount() > 0) {
            providerComboBox.setSelectedIndex(0);
        }
    }

    static LlmProvider[] availableProviders(LlmProvider alwaysInclude) {
        ExtensionLlm extensionLlm = getExtensionLlm();
        return Arrays.stream(LlmProvider.values())
                .filter(provider -> provider != LlmProvider.NONE)
                .filter(
                        provider ->
                                !provider.requiresExternalFactory()
                                        || provider == alwaysInclude
                                        || (extensionLlm != null
                                                && extensionLlm.hasChatModelFactory(provider)))
                .toArray(LlmProvider[]::new);
    }

    private static ExtensionLlm getExtensionLlm() {
        try {
            return Control.getSingleton().getExtensionLoader().getExtension(ExtensionLlm.class);
        } catch (Exception e) {
            return null;
        }
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
        List<String> models = parseModels();
        if (provider.isModelRequired() && models.isEmpty()) {
            View.getSingleton()
                    .showWarningDialog(
                            this,
                            Constant.messages.getString(
                                    provider.isLocalModelPath()
                                            ? "llm.options.providers.error.modelpath.empty"
                                            : "llm.options.providers.error.model.empty"));
            return false;
        }
        if (provider.isLocalModelPath()) {
            for (String modelId : models) {
                if (!isValidLocalModelPath(modelId)) {
                    View.getSingleton()
                            .showWarningDialog(
                                    this,
                                    Constant.messages.getString(
                                            "llm.options.providers.error.modelpath.invalid",
                                            modelId));
                    return false;
                }
            }
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

        String apiKey = new String(apiKeyField.getPassword());
        if (provider != null && !provider.supportsApiKey()) {
            apiKey = "";
        }

        List<String> models = parseModels();
        if (provider != null && provider.isLocalModelPath()) {
            models =
                    models.stream()
                            .map(LocalLlmModelPath::toStoredModelId)
                            .filter(StringUtils::isNotBlank)
                            .distinct()
                            .toList();
        }

        providerConfig =
                new LlmProviderConfig(
                        StringUtils.trimToEmpty(nameTextField.getText()),
                        provider,
                        apiKey,
                        endpoint,
                        models,
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

    protected void updateApiKeyFieldState() {
        LlmProvider provider = (LlmProvider) providerComboBox.getSelectedItem();
        boolean enabled = provider == null || provider.supportsApiKey();
        apiKeyField.setEnabled(enabled);
        if (!enabled) {
            apiKeyField.setText("");
        }
    }

    protected void updateModelsFieldState() {
        LlmProvider provider = (LlmProvider) providerComboBox.getSelectedItem();
        boolean localPath = provider != null && provider.isLocalModelPath();
        modelNameLabel.setText(
                Constant.messages.getString(
                        localPath
                                ? "llm.options.providers.field.modelpath"
                                : "llm.options.providers.field.models"));
        browseModelButton.setVisible(localPath);
        removeModelButton.setVisible(localPath);
        downloadModelButton.setVisible(
                localPath
                        && provider != null
                        && getExtensionLlm() != null
                        && getExtensionLlm().hasLocalModelDownloadUi(provider));
        modelsCardLayout.show(modelsCardsPanel, localPath ? CARD_LOCAL : CARD_REMOTE);
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

    private void browseForModelPath() {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
        File modelsDir = LocalLlmModelPath.getModelsDirectory().toFile();
        if (!modelsDir.isDirectory()) {
            modelsDir.mkdirs();
        }
        if (modelsDir.isDirectory()) {
            chooser.setCurrentDirectory(modelsDir);
        }
        List<String> current = parseLocalModels();
        if (!current.isEmpty()) {
            File currentFile = LocalLlmModelPath.resolveModelDirectory(current.get(0)).toFile();
            if (currentFile.exists()) {
                chooser.setSelectedFile(currentFile);
            } else if (currentFile.getParentFile() != null
                    && currentFile.getParentFile().exists()) {
                chooser.setCurrentDirectory(currentFile.getParentFile());
            }
        }
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            Path selected = normalizeLocalModelPath(chooser.getSelectedFile().getAbsolutePath());
            addLocalModel(selected.toString());
        }
    }

    private void downloadModel() {
        LlmProvider provider = (LlmProvider) providerComboBox.getSelectedItem();
        ExtensionLlm extensionLlm = getExtensionLlm();
        if (provider == null || extensionLlm == null) {
            return;
        }
        LlmLocalModelDownloadUi downloadUi = extensionLlm.getLocalModelDownloadUi(provider);
        if (downloadUi == null) {
            return;
        }
        downloadUi
                .showDownloadDialog(this)
                .map(LocalLlmModelPath::toStoredModelId)
                .ifPresent(this::addLocalModel);
    }

    private void removeSelectedLocalModels() {
        int[] rows = localModelsTable.getSelectedRows();
        for (int i = rows.length - 1; i >= 0; i--) {
            localModelsTableModel.removeRow(rows[i]);
        }
    }

    private void addLocalModel(String modelId) {
        String stored = LocalLlmModelPath.toStoredModelId(modelId);
        if (stored.isEmpty() || parseLocalModels().contains(stored)) {
            return;
        }
        localModelsTableModel.addRow(new Object[] {stored});
    }

    static Path normalizeLocalModelPath(String path) {
        return LocalLlmModelPath.resolveModelDirectory(path);
    }

    static boolean isValidLocalModelPath(String path) {
        return LocalLlmModelPath.isValidModelDirectory(path);
    }

    private List<String> parseModels() {
        LlmProvider provider = (LlmProvider) providerComboBox.getSelectedItem();
        if (provider != null && provider.isLocalModelPath()) {
            return parseLocalModels();
        }
        List<String> models = new ArrayList<>();
        for (String line : modelsArea.getText().split("\\R")) {
            String trimmed = StringUtils.trimToEmpty(line);
            if (!trimmed.isEmpty()) {
                models.add(trimmed);
            }
        }
        return models;
    }

    private List<String> parseLocalModels() {
        List<String> models = new ArrayList<>();
        for (int i = 0; i < localModelsTableModel.getRowCount(); i++) {
            Object value = localModelsTableModel.getValueAt(i, 0);
            if (value != null) {
                String trimmed = StringUtils.trimToEmpty(value.toString());
                if (!trimmed.isEmpty()) {
                    models.add(trimmed);
                }
            }
        }
        return models;
    }
}
