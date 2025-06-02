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

import org.zaproxy.addon.automation.jobs.RequestorJob;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class AddHeaderDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;
    private static final String TITLE = "automation.dialog.header.title";
    private static final String NAME_PARAM = "automation.dialog.header.name";
    private static final String VALUE_PARAM = "automation.dialog.header.value";

    private boolean isNew;
    private AddRequestDialog addReqDialog;
    private RequestorJob.Request.Header header;

    public AddHeaderDialog(AddRequestDialog owner) {
        this(owner, null);
    }

    public AddHeaderDialog(AddRequestDialog owner, RequestorJob.Request.Header header) {
        super(owner, TITLE, DisplayUtils.getScaledDimension(300, 150));
        this.addReqDialog = owner;
        if (header == null) {
            header = new RequestorJob.Request.Header();
            this.isNew = true;
        }
        this.header = header;

        this.addTextField(NAME_PARAM, header.getName());
        this.addTextField(VALUE_PARAM, header.getValue());
    }

    @Override
    public void save() {
        this.header.setName(this.getStringValue(NAME_PARAM));
        this.header.setValue(this.getStringValue(VALUE_PARAM));
        if (this.isNew) {
            addReqDialog.addHeader(header);
        }
    }

    @Override
    public String validateFields() {

        return null;
    }
}
