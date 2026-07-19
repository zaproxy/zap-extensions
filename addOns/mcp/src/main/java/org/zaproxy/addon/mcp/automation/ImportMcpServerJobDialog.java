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
package org.zaproxy.addon.mcp.automation;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class ImportMcpServerJobDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String TITLE = "mcp.importserver.automation.dialog.title";
    private static final String NAME_PARAM = "mcp.importserver.automation.dialog.name";
    private static final String SERVER_URL_PARAM = "mcp.importserver.automation.dialog.serverurl";
    private static final String SECURITY_KEY_PARAM =
            "mcp.importserver.automation.dialog.securitykey";

    private final ImportMcpServerJob job;

    public ImportMcpServerJobDialog(ImportMcpServerJob job) {
        super(View.getSingleton().getMainFrame(), TITLE, DisplayUtils.getScaledDimension(500, 250));
        this.job = job;

        this.addTextField(NAME_PARAM, this.job.getData().getName());
        this.addTextField(SERVER_URL_PARAM, this.job.getParameters().getServerUrl());
        this.addPasswordField(SECURITY_KEY_PARAM, this.job.getParameters().getSecurityKey());
        this.addPadding();
    }

    @Override
    public void save() {
        this.job.getData().setName(this.getStringValue(NAME_PARAM));
        this.job.getParameters().setServerUrl(this.getStringValue(SERVER_URL_PARAM));
        this.job.getParameters().setSecurityKey(this.getStringValue(SECURITY_KEY_PARAM));
        this.job.resetAndSetChanged();
    }

    @Override
    public String validateFields() {
        if (this.getStringValue(SERVER_URL_PARAM).isBlank()) {
            return Constant.messages.getString("mcp.importserver.error.emptyurl");
        }
        return null;
    }
}
