/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.network.internal.ui;

import java.awt.Dialog;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.network.internal.server.http.Alias;

public class ModifyAliasDialog extends AddAliasDialog {

    private static final long serialVersionUID = 1L;

    public ModifyAliasDialog(Dialog owner) {
        super(owner, Constant.messages.getString("network.ui.options.alias.modify.title"));
    }

    @Override
    protected String getConfirmButtonLabel() {
        return Constant.messages.getString("network.ui.options.alias.modify.button");
    }

    public void setAlias(Alias alias) {
        this.alias = alias;
    }

    @Override
    protected void init() {
        nameTextField.setText(alias.getName());
        nameTextField.discardAllEdits();
        enabledCheckBox.setSelected(alias.isEnabled());
    }
}
