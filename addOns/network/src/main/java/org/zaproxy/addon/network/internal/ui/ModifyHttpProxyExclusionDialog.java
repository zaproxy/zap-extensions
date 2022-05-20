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
import org.zaproxy.addon.network.internal.client.HttpProxyExclusion;

public class ModifyHttpProxyExclusionDialog extends AddHttpProxyExclusionDialog {

    private static final long serialVersionUID = 1L;

    public ModifyHttpProxyExclusionDialog(Dialog owner) {
        super(
                owner,
                Constant.messages.getString(
                        "network.ui.options.connection.httpproxy.exclusions.modify.title"));
    }

    @Override
    protected String getConfirmButtonLabel() {
        return Constant.messages.getString(
                "network.ui.options.connection.httpproxy.exclusions.modify.button");
    }

    public void setHttpProxyExclusion(HttpProxyExclusion httpProxyExclusion) {
        this.httpProxyExclusion = httpProxyExclusion;
    }

    @Override
    protected void init() {
        hostTextField.setText(httpProxyExclusion.getHost().pattern());
        hostTextField.discardAllEdits();
        enabledCheckBox.setSelected(httpProxyExclusion.isEnabled());
    }
}
