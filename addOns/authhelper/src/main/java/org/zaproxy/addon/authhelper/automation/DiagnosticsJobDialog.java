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
package org.zaproxy.addon.authhelper.automation;

import org.parosproxy.paros.view.View;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class DiagnosticsJobDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String TITLE = "authhelper.automation.diagnostics.dialog.title";
    private static final String NAME_PARAM = "automation.dialog.all.name";
    private static final String ENABLED_PARAM = "authhelper.automation.diagnostics.dialog.enabled";

    private final DiagnosticsJob job;

    public DiagnosticsJobDialog(DiagnosticsJob job) {
        super(View.getSingleton().getMainFrame(), TITLE, DisplayUtils.getScaledDimension(400, 180));
        this.job = job;

        this.addTextField(NAME_PARAM, this.job.getData().getName());
        this.addCheckBoxField(ENABLED_PARAM, this.job.getParameters().isEnabled());
        this.addPadding();
    }

    @Override
    public void save() {
        this.job.getData().setName(this.getStringValue(NAME_PARAM));
        this.job.getParameters().setEnabled(this.getBoolValue(ENABLED_PARAM));
        this.job.resetAndSetChanged();
    }

    @Override
    public String validateFields() {
        return null;
    }
}
