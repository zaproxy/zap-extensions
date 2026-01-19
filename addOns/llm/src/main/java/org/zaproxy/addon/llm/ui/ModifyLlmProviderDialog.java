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
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.llm.LlmProviderConfig;

public class ModifyLlmProviderDialog extends AddLlmProviderDialog {

    private static final long serialVersionUID = 1L;

    public ModifyLlmProviderDialog(Dialog owner, LlmProviderConfigsTableModel model) {
        super(owner, model);
        setTitle(Constant.messages.getString("llm.options.providers.modify.title"));
    }

    @Override
    protected String getConfirmButtonLabel() {
        return Constant.messages.getString("llm.options.providers.modify.button");
    }

    public void setProviderConfig(LlmProviderConfig providerConfig) {
        this.providerConfig = providerConfig;
        this.originalName = providerConfig.getName();
    }

    @Override
    protected void init() {
        nameTextField.setText(providerConfig.getName());
        providerComboBox.setSelectedItem(providerConfig.getProvider());
        apiKeyField.setText(providerConfig.getApiKey());
        endpointField.setText(providerConfig.getEndpoint());
        modelsArea.setText(String.join("\n", providerConfig.getModels()));
        updateEndpointFieldState();
    }
}
