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

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.addon.llm.LlmOptions;
import org.zaproxy.addon.llm.LlmProvider;
import org.zaproxy.addon.llm.LlmProviderConfig;

@SuppressWarnings("serial")
public class LlmOptionsPanel extends AbstractParamPanel {

    private static final long serialVersionUID = 1L;

    private LlmProviderConfigsTableModel providerConfigsModel;
    private final JComboBox<String> defaultProviderComboBox;
    private final JComboBox<String> defaultModelComboBox;
    private final String noneProviderLabel;

    public LlmOptionsPanel() {
        super();

        setName(Constant.messages.getString("llm.options.title"));

        setLayout(new GridBagLayout());

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.LINE_START;
        gbc.fill = GridBagConstraints.HORIZONTAL;

        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 0.0;
        add(new JLabel(Constant.messages.getString("llm.options.providers.default.label")), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        noneProviderLabel = LlmProvider.NONE.toString();
        defaultProviderComboBox = new JComboBox<>();
        add(defaultProviderComboBox, gbc);

        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.weightx = 0.0;
        add(
                new JLabel(
                        Constant.messages.getString("llm.options.providers.default.model.label")),
                gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        defaultModelComboBox = new JComboBox<>();
        add(defaultModelComboBox, gbc);

        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.gridwidth = 2;
        gbc.weightx = 1.0;
        add(new JLabel(Constant.messages.getString("llm.options.providers.label")), gbc);

        LlmProviderConfigsPanel providerConfigsPanel =
                new LlmProviderConfigsPanel(getProviderConfigsTableModel());
        gbc.gridy = 3;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        add(providerConfigsPanel, gbc);

        getProviderConfigsTableModel()
                .addTableModelListener(
                        new TableModelListener() {
                            @Override
                            public void tableChanged(TableModelEvent e) {
                                refreshDefaultProviderOptions();
                            }
                        });
        defaultProviderComboBox.addActionListener(e -> refreshDefaultModelOptions());
    }

    @Override
    public String getHelpIndex() {
        return "addon.llm.options";
    }

    @Override
    public void initParam(Object options) {
        LlmOptions llmOptionsParam = ((OptionsParam) options).getParamSet(LlmOptions.class);
        getProviderConfigsTableModel().setProviderConfigs(llmOptionsParam.getProviderConfigs());
        refreshDefaultProviderOptions();
        if (llmOptionsParam.getDefaultProviderName() == null
                || llmOptionsParam.getDefaultProviderName().isEmpty()) {
            defaultProviderComboBox.setSelectedItem(noneProviderLabel);
        } else {
            defaultProviderComboBox.setSelectedItem(llmOptionsParam.getDefaultProviderName());
        }
        setFirstItemIfUnset(defaultProviderComboBox);
        refreshDefaultModelOptions();
        defaultModelComboBox.setSelectedItem(llmOptionsParam.getDefaultModelName());
        setFirstItemIfUnset(defaultModelComboBox);
    }

    @Override
    public void saveParam(Object options) {
        LlmOptions param = ((OptionsParam) options).getParamSet(LlmOptions.class);
        param.setProviderConfigs(getProviderConfigsTableModel().getElements());
        Object selected = defaultProviderComboBox.getSelectedItem();
        if (selected != null && noneProviderLabel.equals(selected.toString())) {
            param.setDefaultProviderName("");
            param.setDefaultModelName("");
        } else {
            param.setDefaultProviderName(selected != null ? selected.toString() : "");
            Object selectedModel = defaultModelComboBox.getSelectedItem();
            param.setDefaultModelName(selectedModel != null ? selectedModel.toString() : "");
        }
    }

    private LlmProviderConfigsTableModel getProviderConfigsTableModel() {
        if (providerConfigsModel == null) {
            providerConfigsModel = new LlmProviderConfigsTableModel();
        }
        return providerConfigsModel;
    }

    private void refreshDefaultProviderOptions() {
        Object selected = defaultProviderComboBox.getSelectedItem();
        defaultProviderComboBox.removeAllItems();
        defaultProviderComboBox.addItem(noneProviderLabel);
        for (LlmProviderConfig config : getProviderConfigsTableModel().getElements()) {
            defaultProviderComboBox.addItem(config.getName());
        }
        if (selected != null) {
            defaultProviderComboBox.setSelectedItem(selected);
        }
        setFirstItemIfUnset(defaultProviderComboBox);
    }

    private void refreshDefaultModelOptions() {
        Object selected = defaultModelComboBox.getSelectedItem();
        defaultModelComboBox.removeAllItems();
        LlmProviderConfig config = getSelectedProviderConfig();
        if (config == null && noneProviderLabel.equals(defaultProviderComboBox.getSelectedItem())) {
            return;
        }
        if (config != null) {
            for (String model : config.getModels()) {
                defaultModelComboBox.addItem(model);
            }
        }
        if (selected != null) {
            defaultModelComboBox.setSelectedItem(selected);
        }
        setFirstItemIfUnset(defaultModelComboBox);
    }

    private void setFirstItemIfUnset(JComboBox<String> box) {
        if (box.getSelectedItem() == null && box.getItemCount() > 0) {
            box.setSelectedIndex(0);
        }
    }

    private LlmProviderConfig getSelectedProviderConfig() {
        Object selected = defaultProviderComboBox.getSelectedItem();
        if (selected == null) {
            return null;
        }
        String name = selected.toString();
        if (noneProviderLabel.equals(name)) {
            return null;
        }
        for (LlmProviderConfig config : getProviderConfigsTableModel().getElements()) {
            if (name.equals(config.getName())) {
                return config;
            }
        }
        return null;
    }
}
