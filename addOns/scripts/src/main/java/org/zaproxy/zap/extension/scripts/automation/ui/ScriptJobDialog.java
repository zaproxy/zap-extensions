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
package org.zaproxy.zap.extension.scripts.automation.ui;

import java.util.ArrayList;
import java.util.List;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.scripts.automation.ScriptJob;
import org.zaproxy.zap.extension.scripts.automation.actions.ScriptAction;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

public class ScriptJobDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String TITLE = "scripts.automation.dialog.title";
    private static final String NAME_PARAM = "scripts.automation.dialog.name";
    private static final String SCRIPT_ACTION_PARAM = "scripts.automation.dialog.action";
    private static final String SCRIPT_TYPE_PARAM = "scripts.automation.dialog.scriptType";
    private static final String SCRIPT_NAME_PARAM = "scripts.automation.dialog.scriptName";

    private ScriptJob job;

    public ScriptJobDialog(ScriptJob job) {
        super(View.getSingleton().getMainFrame(), TITLE, DisplayUtils.getScaledDimension(300, 200));
        this.job = job;

        this.addTextField(NAME_PARAM, this.job.getData().getName());
        this.addComboField(
                SCRIPT_ACTION_PARAM,
                ScriptJob.validActions(),
                this.job.getData().getParameters().getAction(),
                false);
        this.addFieldListener(SCRIPT_ACTION_PARAM, e -> onScriptActionChanged());
        this.addComboField(
                SCRIPT_TYPE_PARAM,
                new ArrayList<>(),
                this.job.getData().getParameters().getType(),
                false);
        this.addFieldListener(SCRIPT_TYPE_PARAM, e -> onScriptTypeChanged());
        this.addComboField(
                SCRIPT_NAME_PARAM,
                new ArrayList<>(),
                this.job.getData().getParameters().getName(),
                true);
        this.addPadding();

        onScriptActionChanged();
        onScriptTypeChanged();
    }

    private void onScriptActionChanged() {
        String action = this.getStringValue(SCRIPT_ACTION_PARAM);
        List<String> scriptTypes = ScriptJob.validScriptTypesForAction(action);
        this.setComboFields(
                SCRIPT_TYPE_PARAM, scriptTypes, this.job.getData().getParameters().getType());
    }

    private void onScriptTypeChanged() {
        String scriptType = this.getStringValue(SCRIPT_TYPE_PARAM);
        List<String> scripts = ScriptAction.getAvailableScriptNames(scriptType);
        this.setComboFields(
                SCRIPT_NAME_PARAM, scripts, this.job.getData().getParameters().getName());
    }

    @Override
    public void save() {
        this.job.getData().setName(this.getStringValue(NAME_PARAM));
        this.job.getData().getParameters().setAction(this.getStringValue(SCRIPT_ACTION_PARAM));
        this.job.getData().getParameters().setType(this.getStringValue(SCRIPT_TYPE_PARAM));
        this.job.getData().getParameters().setName(this.getStringValue(SCRIPT_NAME_PARAM));
        this.job.resetAndSetChanged();
    }

    @Override
    public String validateFields() {
        return null;
    }
}
