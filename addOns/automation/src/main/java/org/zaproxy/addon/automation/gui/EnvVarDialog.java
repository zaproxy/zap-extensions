/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
public class EnvVarDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String TITLE = "automation.dialog.envvar.title";
    private static final String KEY_PARAM = "automation.dialog.envvar.key";
    private static final String VALUE_PARAM = "automation.dialog.envvar.value";

    private boolean isNew = false;
    private EnvironmentDialog envDialog;
    private EnvVarTableModel.EnvVar envVar;

    public EnvVarDialog(EnvironmentDialog owner) {
        this(owner, null);
    }

    public EnvVarDialog(EnvironmentDialog owner, EnvVarTableModel.EnvVar envVar) {
        super(owner, TITLE, DisplayUtils.getScaledDimension(300, 150));
        this.envDialog = owner;
        if (envVar == null) {
            envVar = new EnvVarTableModel.EnvVar();
            this.isNew = true;
        }
        this.envVar = envVar;

        this.addTextField(KEY_PARAM, envVar.getKey());
        this.addTextField(VALUE_PARAM, envVar.getValue());
    }

    @Override
    public void save() {
        this.envVar.setKey(this.getStringValue(KEY_PARAM).trim());
        this.envVar.setValue(this.getStringValue(VALUE_PARAM).trim());
        if (this.isNew) {
            envDialog.addEnvVar(envVar);
        }
    }

    @Override
    public String validateFields() {
        if (this.getStringValue(KEY_PARAM).trim().isEmpty()) {
            return Constant.messages.getString("automation.dialog.envvar.error.badkey");
        }
        return null;
    }
}
