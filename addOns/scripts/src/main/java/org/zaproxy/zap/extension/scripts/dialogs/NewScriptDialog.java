/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.scripts.dialogs;

import java.awt.Dimension;
import java.awt.Frame;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.script.ScriptEngineWrapper;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.scripts.ExtensionScriptsUI;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class NewScriptDialog extends StandardFieldsDialog {

    private static final String FIELD_NAME = "scripts.dialog.script.label.name";
    private static final String FIELD_ENGINE = "scripts.dialog.script.label.engine";
    private static final String FIELD_DESC = "scripts.dialog.script.label.desc";
    private static final String FIELD_TEMPLATE = "scripts.dialog.script.label.template";
    private static final String FIELD_TYPE = "scripts.dialog.script.label.type";
    private static final String FIELD_LOAD = "scripts.dialog.script.label.load";
    private static final String FIELD_ENABLED = "scripts.dialog.script.label.enabled";

    private static final long serialVersionUID = 1L;

    private ExtensionScriptsUI extension = null;

    public NewScriptDialog(
            ExtensionScriptsUI ext, Frame owner, Dimension dim, ScriptWrapper template) {
        super(owner, "scripts.dialog.script.new.title", dim);
        this.extension = ext;
        init(template);
    }

    public void init(ScriptType type) {
        this.setFieldValue(FIELD_NAME, "");
        this.setFieldValue(FIELD_DESC, "");
        this.setComboFields(FIELD_TYPE, this.getTypes(), "");
        this.setComboFields(FIELD_ENGINE, this.getEngines(), "");
        this.setComboFields(FIELD_TEMPLATE, this.getTemplates(), "");

        if (type == null) {
            this.setFieldValue(FIELD_TYPE, "");
        } else {
            this.setFieldValue(FIELD_TYPE, Constant.messages.getString(type.getI18nKey()));
        }
    }

    public void init(ScriptWrapper template) {
        String name = "";
        String desc = "";
        String type = "";
        String engine = "";
        String templateName = "";

        if (template != null) {
            name = template.getName();
            desc = template.getDescription();
            type = Constant.messages.getString(template.getType().getI18nKey());
            engine = template.getEngineName();
            try {
                // Nasty, but it works ;)
                engine =
                        extension
                                .getExtScript()
                                .getEngineNameForExtension(
                                        template.getEngine().getExtensions().get(0));
            } catch (Exception e1) {
                // Ignore
            }
            templateName = template.getName();
        }

        this.removeAllFields();

        this.setTitle(Constant.messages.getString("scripts.dialog.script.new.title"));
        this.addTextField(FIELD_NAME, name);
        this.addComboField(FIELD_TYPE, this.getTypes(), type);
        this.addComboField(FIELD_ENGINE, this.getEngines(), engine);
        this.addComboField(FIELD_TEMPLATE, this.getTemplates(), templateName);
        this.addMultilineField(FIELD_DESC, desc);
        this.addCheckBoxField(FIELD_LOAD, true);
        this.addCheckBoxField(FIELD_ENABLED, false);
        if (template == null) {
            this.getField(FIELD_ENABLED).setEnabled(false);
        } else {
            this.getField(FIELD_ENABLED).setEnabled(template.getType().isEnableable());
            this.setFieldValue(FIELD_ENABLED, template.getType().isEnabledByDefault());
        }

        this.addFieldListener(
                FIELD_TYPE,
                e -> {
                    boolean scriptEnableable = false;
                    boolean scriptEnabledByDefault = false;

                    if (isEmptyField(FIELD_TYPE)) {
                        // Unset the template, otherwise it just resets the type again ;)
                        if (!isEmptyField(FIELD_ENGINE)) {
                            setFieldValue(FIELD_ENGINE, "");
                        }
                        setFieldValue(FIELD_TEMPLATE, "");
                    } else {
                        ScriptType scriptType = nameToType(getStringValue(FIELD_TYPE));
                        if (scriptType != null) {
                            scriptEnableable = scriptType.isEnableable();
                            scriptEnabledByDefault = scriptType.isEnabledByDefault();
                        }
                    }
                    getField(FIELD_ENABLED).setEnabled(scriptEnableable);
                    setFieldValue(FIELD_ENABLED, scriptEnabledByDefault);

                    resetTemplates();
                });

        this.addFieldListener(
                FIELD_ENGINE,
                e -> {
                    if (isEmptyField(FIELD_ENGINE)) {
                        // Unset the template, otherwise it just resets the engine again ;)
                        setFieldValue(FIELD_TEMPLATE, "");
                    }
                    resetTemplates();
                });

        this.addPadding();
    }

    private void resetTemplates() {
        List<String> templates = getTemplates();
        if (templates.isEmpty()) {
            // None to select :(
            setComboFields(FIELD_TEMPLATE, templates, "");
        } else if (!this.isEmptyField(FIELD_TEMPLATE)
                && templates.contains(getStringValue(FIELD_TEMPLATE))) {
            // Current selected one is still valid
            setComboFields(FIELD_TEMPLATE, templates, getStringValue(FIELD_TEMPLATE));
        } else if (templates.size() == 1) {
            // Only one - select that template
            setComboFields(FIELD_TEMPLATE, templates, templates.get(0));
        } else {
            // Default to none
            setComboFields(FIELD_TEMPLATE, templates, "");
        }
    }

    private List<String> getEngines() {
        ArrayList<String> list = new ArrayList<>();
        int engineCount = extension.getExtScript().getScriptingEngines().size();
        if (engineCount > 1) {
            list.add("");
        }
        list.addAll(extension.getExtScript().getScriptingEngines());
        return list;
    }

    private List<String> getTypes() {
        ArrayList<String> list = new ArrayList<>();
        list.add("");
        for (ScriptType type : extension.getExtScript().getScriptTypes()) {
            if (type.hasCapability(ExtensionScriptsUI.CAPABILITY_EXTERNAL)) {
                // Ignore
                continue;
            }
            list.add(Constant.messages.getString(type.getI18nKey()));
        }
        Collections.sort(list);
        return list;
    }

    private ScriptType nameToType(String name) {
        for (ScriptType type : extension.getExtScript().getScriptTypes()) {
            if (Constant.messages.getString(type.getI18nKey()).equals(name)) {
                return type;
            }
        }
        return null;
    }

    private ScriptEngineWrapper getSelectedEngine() {
        if (this.isEmptyField(FIELD_ENGINE)) {
            return null;
        }
        return extension.getExtScript().getEngineWrapper(this.getStringValue(FIELD_ENGINE));
    }

    private List<String> getTemplates() {
        ArrayList<String> list = new ArrayList<>();
        ScriptEngineWrapper selectedEngine = getSelectedEngine();
        for (ScriptWrapper template :
                extension
                        .getExtScript()
                        .getTreeModel()
                        .getTemplates(this.nameToType(this.getStringValue(FIELD_TYPE)))) {

            if (template.getEngine() != null
                    && (selectedEngine == null || template.getEngine().equals(selectedEngine))) {
                list.add(template.getName());
            }
        }
        if (list.size() > 1
                && (selectedEngine == null || selectedEngine.isSupportsMissingTemplates())) {
            // Only give an empty choice if theres more than one (and the engine does not require
            // template)
            list.add(0, "");
        }
        return list;
    }

    @Override
    public void save() {
        ScriptWrapper script = new ScriptWrapper();
        script.setType(this.nameToType(this.getStringValue(FIELD_TYPE)));

        if (!this.isEmptyField(FIELD_TEMPLATE)) {
            // Template overrides everything else - will match the other fields anyway
            ScriptWrapper template =
                    extension
                            .getExtScript()
                            .getTreeModel()
                            .getTemplate(this.getStringValue(FIELD_TEMPLATE));
            script.setContents(template.getContents());
            script.setType(template.getType());
            script.setEngine(template.getEngine());
        } else {
            // Template not set, create a blank script
            ScriptEngineWrapper ew = getSelectedEngine();
            script.setEngine(ew);
            script.setType(this.nameToType(this.getStringValue(FIELD_TYPE)));
        }

        script.setName(this.getStringValue(FIELD_NAME));
        script.setDescription(this.getStringValue(FIELD_DESC));
        script.setLoadOnStart(this.getBoolValue(FIELD_LOAD));
        script.setEnabled(getBoolValue(FIELD_ENABLED));

        extension.getExtScript().addScript(script);
    }

    @Override
    public String validateFields() {
        if (this.isEmptyField(FIELD_NAME)) {
            return Constant.messages.getString("scripts.dialog.script.error.name");
        }
        if (this.isEmptyField(FIELD_TEMPLATE)
                && (this.isEmptyField(FIELD_TYPE) || this.isEmptyField(FIELD_ENGINE))) {
            // Must specify template or both the type and engine
            return Constant.messages.getString("scripts.dialog.script.error.template");
        }
        if (extension.getExtScript().getScript(this.getStringValue(FIELD_NAME)) != null) {
            return Constant.messages.getString("scripts.dialog.script.error.duplicate");
        }
        if (this.isEmptyField(FIELD_TEMPLATE)) {
            // No template, check the engine supports this
            if (!getSelectedEngine().isSupportsMissingTemplates()) {
                return Constant.messages.getString("scripts.dialog.script.error.notemplate");
            }
        }

        return null;
    }
}
