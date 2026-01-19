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

import java.util.List;
import javax.swing.ButtonGroup;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JRadioButtonMenuItem;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.llm.ExtensionLlm;
import org.zaproxy.addon.llm.LlmOptions;
import org.zaproxy.addon.llm.LlmProvider;
import org.zaproxy.addon.llm.LlmProviderConfig;

@SuppressWarnings("serial")
public class LlmSelectorButton extends JButton {

    private static final long serialVersionUID = 1L;
    private ExtensionLlm ext;
    private LlmOptions options;

    public LlmSelectorButton(ExtensionLlm ext, LlmOptions options) {
        this.ext = ext;
        this.options = options;
        setIcon(
                new ImageIcon(
                        ExtensionLlm.class.getResource(
                                "/org/zaproxy/addon/llm/resources/agent.png")));
        setToolTipText(Constant.messages.getString("llm.toolbar.button.tooltip"));
        addActionListener(e -> showProvidersPopup());
    }

    private void showProvidersPopup() {
        JPopupMenu menu = buildProvidersMenu();
        menu.show(this, 0, this.getHeight());
    }

    private JPopupMenu buildProvidersMenu() {
        JPopupMenu menu = new JPopupMenu();
        List<LlmProviderConfig> configs = options.getProviderConfigs();
        String noneLabel = LlmProvider.NONE.toString();
        String defaultName = options.getDefaultProviderName();
        String defaultModel = options.getDefaultModelName();
        boolean noneSelected = defaultName == null || defaultName.isEmpty();
        ButtonGroup group = new ButtonGroup();
        addProviderModelItem(menu, group, noneLabel, "", noneSelected);

        if (configs.isEmpty()) {
            JMenuItem empty =
                    new JMenuItem(Constant.messages.getString("llm.toolbar.providers.none"));
            empty.setEnabled(false);
            menu.add(empty);
            return menu;
        }

        for (LlmProviderConfig config : configs) {
            String name = config.getName();
            List<String> models = config.getModels();
            if (models.isEmpty()) {
                addProviderModelItem(
                        menu,
                        group,
                        name,
                        "",
                        name.equals(defaultName) && StringUtils.isEmpty(defaultModel));
                continue;
            }
            for (String model : models) {
                boolean isDefault = name.equals(defaultName) && model.equals(defaultModel);
                addProviderModelItem(menu, group, name, model, isDefault);
            }
        }
        return menu;
    }

    private void addProviderModelItem(
            JPopupMenu menu,
            ButtonGroup group,
            String providerName,
            String modelName,
            boolean isDefault) {
        String label = providerName;
        if (!modelName.isEmpty()) {
            label += " - " + modelName;
        } else {
            if (!providerName.equals(LlmProvider.NONE.toString())) {
                label += " - " + Constant.messages.getString("llm.toolbar.model.empty");
            }
        }
        if (isDefault) {
            label += Constant.messages.getString("llm.toolbar.default.suffix");
        }

        JRadioButtonMenuItem item = new JRadioButtonMenuItem(label, isDefault);
        item.addActionListener(e -> ext.setDefaultProvider(providerName, modelName));
        group.add(item);
        menu.add(item);
    }
}
