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
package org.zaproxy.addon.automation.gui;

import org.parosproxy.paros.Constant;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class ConfigsDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String TITLE = "automation.dialog.configs.title";
    // Deliberate reuse of the envvar strings
    private static final String KEY_PARAM = "automation.dialog.envvar.key";
    private static final String VALUE_PARAM = "automation.dialog.envvar.value";

    private boolean isNew = false;
    private EnvironmentDialog configsDialog;
    private ConfigsTableModel.Config configs;

    public ConfigsDialog(EnvironmentDialog owner) {
        this(owner, null);
    }

    public ConfigsDialog(EnvironmentDialog owner, ConfigsTableModel.Config configs) {
        super(owner, TITLE, DisplayUtils.getScaledDimension(300, 150));
        this.configsDialog = owner;
        if (configs == null) {
            configs = new ConfigsTableModel.Config();
            this.isNew = true;
        }
        this.configs = configs;

        this.addTextField(KEY_PARAM, configs.getKey());
        this.addTextField(VALUE_PARAM, configs.getValue());
    }

    @Override
    public void save() {
        this.configs.setKey(this.getStringValue(KEY_PARAM).trim());
        this.configs.setValue(this.getStringValue(VALUE_PARAM).trim());
        if (this.isNew) {
            configsDialog.addConfigs(configs);
        }
    }

    @Override
    public String validateFields() {
        if (this.getStringValue(KEY_PARAM).trim().isEmpty()) {
            return Constant.messages.getString("automation.dialog.Configs.error.badkey");
        }
        return null;
    }
}
