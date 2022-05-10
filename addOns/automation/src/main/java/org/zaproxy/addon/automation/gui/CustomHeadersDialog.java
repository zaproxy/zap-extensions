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
package org.zaproxy.addon.automation.gui;

import org.parosproxy.paros.Constant;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

public class CustomHeadersDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;
    private static final String TITLE = "automation.dialog.customheader.title";
    private static final String NAME_PARAM = "automation.dialog.customheader.name";
    private static final String VALUE_PARAM = "automation.dialog.customheader.value";

    private boolean isNew = false;
    private AddRequestDialog addReqDialog;
    private CustomHeadersTableModel.CustomHeader cusHeader;

    public CustomHeadersDialog(AddRequestDialog owner) {
        this(owner, null);
    }

    public CustomHeadersDialog(
            AddRequestDialog owner, CustomHeadersTableModel.CustomHeader cusHeader) {
        super(owner, TITLE, DisplayUtils.getScaledDimension(300, 150));
        this.addReqDialog = owner;
        if (cusHeader == null) {
            cusHeader = new CustomHeadersTableModel.CustomHeader();
            this.isNew = true;
        }
        this.cusHeader = cusHeader;

        this.addTextField(NAME_PARAM, cusHeader.getName());
        this.addTextField(VALUE_PARAM, cusHeader.getValue());
    }

    @Override
    public void save() {
        this.cusHeader.setName(this.getStringValue(NAME_PARAM).trim());
        this.cusHeader.setValue(this.getStringValue(VALUE_PARAM).trim());
        if (this.isNew) {
            addReqDialog.addCustomHeader(cusHeader);
        }
    }

    @Override
    public String validateFields() {
        if (this.getStringValue(NAME_PARAM).trim().isEmpty()) {
            return Constant.messages.getString("automation.dialog.customheader.error.badname");
        }
        return null;
    }
}
