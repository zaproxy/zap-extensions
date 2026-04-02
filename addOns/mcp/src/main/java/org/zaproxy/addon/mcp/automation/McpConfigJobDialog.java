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
import org.zaproxy.addon.mcp.McpParam;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class McpConfigJobDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String TITLE = "mcp.configjob.dialog.title";
    private static final String NAME_PARAM = "mcp.configjob.dialog.name";
    private static final String ENABLED_PARAM = "mcp.configjob.dialog.enabled";
    private static final String PORT_PARAM = "mcp.configjob.dialog.port";
    private static final String SECURITY_KEY_ENABLED_PARAM =
            "mcp.configjob.dialog.securitykeyenabled";
    private static final String SECURITY_KEY_PARAM = "mcp.configjob.dialog.securitykey";

    private final McpConfigJob job;

    public McpConfigJobDialog(McpConfigJob job) {
        super(View.getSingleton().getMainFrame(), TITLE, DisplayUtils.getScaledDimension(500, 300));
        this.job = job;

        McpConfigJob.Parameters p = job.getParameters();
        this.addTextField(NAME_PARAM, job.getData().getName());
        this.addCheckBoxField(ENABLED_PARAM, !Boolean.FALSE.equals(p.getEnabled()));
        this.addNumberField(
                PORT_PARAM, 1, 65535, p.getPort() != null ? p.getPort() : McpParam.DEFAULT_PORT);
        this.addCheckBoxField(
                SECURITY_KEY_ENABLED_PARAM, !Boolean.FALSE.equals(p.getSecurityKeyEnabled()));
        this.addPasswordField(
                SECURITY_KEY_PARAM, p.getSecurityKey() != null ? p.getSecurityKey() : "");
        this.addPadding();
    }

    @Override
    public void save() {
        job.getData().setName(this.getStringValue(NAME_PARAM));
        job.getParameters().setEnabled(this.getBoolValue(ENABLED_PARAM));
        job.getParameters().setPort(this.getIntValue(PORT_PARAM));
        job.getParameters().setSecurityKeyEnabled(this.getBoolValue(SECURITY_KEY_ENABLED_PARAM));
        job.getParameters().setSecurityKey(this.getStringValue(SECURITY_KEY_PARAM));
        job.resetAndSetChanged();
    }

    @Override
    public String validateFields() {
        int port = this.getIntValue(PORT_PARAM);
        if (port < 1 || port > 65535) {
            return Constant.messages.getString("mcp.optionspanel.port.error.invalid");
        }
        if (this.getBoolValue(SECURITY_KEY_ENABLED_PARAM)
                && this.getStringValue(SECURITY_KEY_PARAM).isBlank()) {
            return Constant.messages.getString("mcp.optionspanel.securitykey.error.empty");
        }
        return null;
    }
}
