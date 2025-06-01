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
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

public class AddAddOnsDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String TITLE = "automation.dialog.addaddon.title";
    private static final String ADDON_ID_PARAM = "automation.dialog.addaddon.id";

    private AddOnsTableModel model;

    public AddAddOnsDialog(AddOnsTableModel model) {
        super(View.getSingleton().getMainFrame(), TITLE, DisplayUtils.getScaledDimension(300, 200));
        this.model = model;

        this.addTextField(ADDON_ID_PARAM, "");
        this.addPadding();
    }

    @Override
    public void save() {
        this.model.add(this.getStringValue(ADDON_ID_PARAM));
    }

    @Override
    public String validateFields() {
        if (this.isEmptyField(ADDON_ID_PARAM)) {
            return Constant.messages.getString("automation.dialog.addon.error.noname");
        }
        // Nothing to do
        return null;
    }
}
