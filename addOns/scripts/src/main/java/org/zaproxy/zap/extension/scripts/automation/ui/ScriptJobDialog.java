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

import java.awt.Component;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import javax.swing.JFileChooser;
import javax.swing.JTextField;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.scripts.automation.ScriptJob;
import org.zaproxy.zap.extension.scripts.automation.ScriptJobParameters;
import org.zaproxy.zap.extension.scripts.automation.actions.RunScriptAction;
import org.zaproxy.zap.extension.scripts.automation.actions.ScriptAction;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class ScriptJobDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String TITLE = "scripts.automation.dialog.title";
    public static final String NAME_PARAM = "scripts.automation.dialog.name";
    public static final String SCRIPT_ACTION_PARAM = "scripts.automation.dialog.action";
    public static final String SCRIPT_TYPE_PARAM = "scripts.automation.dialog.scriptType";
    public static final String SCRIPT_ENGINE_PARAM = "scripts.automation.dialog.scriptEngine";
    public static final String SCRIPT_NAME_PARAM = "scripts.automation.dialog.scriptName";
    public static final String SCRIPT_FILE_PARAM = "scripts.automation.dialog.scriptFile";
    public static final String SCRIPT_TARGET_PARAM = "scripts.automation.dialog.target";

    private static final String[] ALL_FIELDS = {
        NAME_PARAM,
        SCRIPT_ACTION_PARAM,
        SCRIPT_TYPE_PARAM,
        SCRIPT_ENGINE_PARAM,
        SCRIPT_NAME_PARAM,
        SCRIPT_FILE_PARAM,
        SCRIPT_TARGET_PARAM
    };

    private ScriptJob job;

    public ScriptJobDialog(ScriptJob job) {
        super(View.getSingleton().getMainFrame(), TITLE, DisplayUtils.getScaledDimension(400, 325));
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
        List<String> engineList = new ArrayList<>(ScriptAction.getScriptingEngines());
        engineList.add(0, "");
        this.addComboField(
                SCRIPT_ENGINE_PARAM,
                engineList,
                this.job.getData().getParameters().getEngine(),
                false);
        this.addComboField(
                SCRIPT_NAME_PARAM,
                new ArrayList<>(),
                this.job.getData().getParameters().getName(),
                true);
        this.addFieldListener(SCRIPT_NAME_PARAM, e -> onScriptNameChanged());
        String fileName = this.job.getData().getParameters().getFile();
        File f;
        if (StringUtils.isEmpty(fileName)) {
            f = getDefaultDirectory();
        } else {
            f = new File(fileName);
        }
        this.addFileSelectField(SCRIPT_FILE_PARAM, f, JFileChooser.FILES_ONLY, null);
        // Cannot select the node as it might not be present in the Sites tree
        this.addNodeSelectField(SCRIPT_TARGET_PARAM, null, true, false);
        Component scriptTargetField = this.getField(SCRIPT_TARGET_PARAM);
        if (scriptTargetField instanceof JTextField) {
            ((JTextField) scriptTargetField)
                    .setText(this.job.getData().getParameters().getTarget());
        }

        this.addPadding();

        onScriptActionChanged();
        onScriptTypeChanged();
    }

    private File getDefaultDirectory() {
        return new File(System.getProperty("user.home"));
    }

    private ScriptAction getScriptAction() {
        return ScriptJob.createScriptAction(
                new ScriptJobParameters(this.getStringValue(SCRIPT_ACTION_PARAM)), null);
    }

    private void onScriptActionChanged() {
        ScriptAction sa = getScriptAction();
        List<String> scriptTypes = sa.getSupportedScriptTypes();
        this.setComboFields(
                SCRIPT_TYPE_PARAM, scriptTypes, this.job.getData().getParameters().getType());

        List<String> disabledFields = sa.getDisabledFields();
        for (String fieldName : ALL_FIELDS) {
            if (disabledFields.contains(fieldName)) {
                this.getField(fieldName).setEnabled(false);
                this.setFieldValue(fieldName, "");
            } else {
                this.getField(fieldName).setEnabled(true);
            }
        }

        onScriptTypeChanged();
    }

    private void onScriptTypeChanged() {
        String scriptType = this.getStringValue(SCRIPT_TYPE_PARAM);

        onScriptTypeTarget(scriptType);

        List<String> scripts = ScriptAction.getAvailableScriptNames(scriptType);
        // Always have a blank option at the start
        scripts.add(0, "");
        this.setComboFields(
                SCRIPT_NAME_PARAM, scripts, this.job.getData().getParameters().getName());
    }

    private void onScriptNameChanged() {
        ScriptAction sa = getScriptAction();
        if (sa.getDisabledFields().contains(SCRIPT_FILE_PARAM)) {
            String scriptName = this.getStringValue(SCRIPT_NAME_PARAM);
            ScriptWrapper sw = ScriptAction.getExtScript().getScript(scriptName);
            if (sw != null) {
                this.setFieldValue(SCRIPT_FILE_PARAM, sw.getFile().getAbsolutePath());
            }
        }
    }

    @Override
    public void save() {
        this.job.getData().setName(this.getStringValue(NAME_PARAM));
        this.job.getData().getParameters().setAction(this.getStringValue(SCRIPT_ACTION_PARAM));
        this.job.getData().getParameters().setType(this.getStringValue(SCRIPT_TYPE_PARAM));
        this.job.getData().getParameters().setEngine(this.getStringValue(SCRIPT_ENGINE_PARAM));
        this.job.getData().getParameters().setName(this.getStringValue(SCRIPT_NAME_PARAM));
        this.job.getData().getParameters().setTarget(this.getStringValue(SCRIPT_TARGET_PARAM));

        ScriptAction sa = getScriptAction();
        if (sa.getDisabledFields().contains(SCRIPT_FILE_PARAM)) {
            this.job.getData().getParameters().setFile(null);
        } else {
            File f = new File(this.getStringValue(SCRIPT_FILE_PARAM));
            if (f.isFile()) {
                this.job.getData().getParameters().setFile(this.getStringValue(SCRIPT_FILE_PARAM));
            }
        }
        this.job.resetAndSetChanged();
    }

    @Override
    public String validateFields() {
        ScriptAction sa = getScriptAction();
        if (sa.getDisabledFields().contains(SCRIPT_FILE_PARAM)) {
            // Always unset this as the text field cannot be edited
            this.setFieldValue(SCRIPT_FILE_PARAM, null);
        }
        ScriptJobParameters params =
                new ScriptJobParameters(
                        this.getStringValue(SCRIPT_ACTION_PARAM),
                        this.getStringValue(SCRIPT_TYPE_PARAM),
                        this.getStringValue(SCRIPT_ENGINE_PARAM),
                        this.getStringValue(SCRIPT_NAME_PARAM),
                        this.getStringValue(SCRIPT_FILE_PARAM),
                        this.getStringValue(SCRIPT_TARGET_PARAM));
        sa = ScriptJob.createScriptAction(params, null);
        List<String> issues = sa.verifyParameters(this.getStringValue(NAME_PARAM), params, null);
        if (issues.isEmpty()) {
            // No problems
            return null;
        }
        return issues.stream().collect(Collectors.joining("\n"));
    }

    private void onScriptTypeTarget(String scriptType) {
        if (RunScriptAction.NAME.equals(getScriptAction().getName())) {
            if (ExtensionScript.TYPE_TARGETED.equals(scriptType)) {
                this.getField(SCRIPT_TARGET_PARAM).setEnabled(true);
                this.getField(SCRIPT_ENGINE_PARAM).setEnabled(true);
            } else {
                this.getField(SCRIPT_TARGET_PARAM).setEnabled(false);
                this.setFieldValue(SCRIPT_TARGET_PARAM, "");
                this.getField(SCRIPT_ENGINE_PARAM).setEnabled(false);
                this.setFieldValue(SCRIPT_ENGINE_PARAM, "");
            }
        }
    }
}
