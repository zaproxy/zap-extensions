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
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptEngineWrapper;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.scripts.ExtensionScriptsUI;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class LoadScriptDialog extends StandardFieldsDialog {

    private static final String FIELD_FILE = "scripts.dialog.script.label.file";
    private static final String FIELD_NAME = "scripts.dialog.script.label.name";
    private static final String FIELD_ENGINE = "scripts.dialog.script.label.engine";
    private static final String FIELD_DESC = "scripts.dialog.script.label.desc";
    private static final String FIELD_TYPE = "scripts.dialog.script.label.type";
    private static final String FIELD_LOAD = "scripts.dialog.script.label.load";
    private static final String FIELD_ENABLED = "scripts.dialog.script.label.enabled";

    private static final long serialVersionUID = 1L;

    private ExtensionScriptsUI extension = null;
    private ScriptWrapper script = null;

    public LoadScriptDialog(ExtensionScriptsUI ext, Frame owner, Dimension dim) {
        super(owner, "scripts.dialog.script.load.title", dim);
        this.extension = ext;
        init();
    }

    private void init() {
        // TODO this should really be a load file

        this.setTitle(Constant.messages.getString("scripts.dialog.script.load.title"));
        this.addTextField(FIELD_NAME, "");
        this.addComboField(
                FIELD_ENGINE, getEngines(), Constant.messages.getString("script.type.standalone"));
        this.addComboField(FIELD_TYPE, this.getTypes(), "");
        this.addMultilineField(FIELD_DESC, "");
        this.addCheckBoxField(FIELD_LOAD, true);
        this.addCheckBoxField(FIELD_ENABLED, false);
        this.getField(FIELD_ENABLED).setEnabled(false);
        this.addFieldListener(
                FIELD_ENGINE,
                e -> {
                    // Change the types based on which engine is selected
                    ScriptEngineWrapper sew =
                            extension.getExtScript().getEngineWrapper(getStringValue(FIELD_ENGINE));
                    if (sew.isRawEngine()) {
                        // Raw engines can only support targeted scripts as there will be no
                        // templates
                        ScriptType tsa =
                                extension
                                        .getExtScript()
                                        .getScriptType(ExtensionScript.TYPE_STANDALONE);
                        setComboFields(
                                FIELD_TYPE,
                                new String[] {Constant.messages.getString(tsa.getI18nKey())},
                                Constant.messages.getString(tsa.getI18nKey()));
                    } else {
                        setComboFields(FIELD_TYPE, getTypes(), "");
                    }
                });

        this.addFieldListener(
                FIELD_TYPE,
                e -> {
                    boolean scriptEnableable = false;
                    boolean scriptEnabledByDefault = false;

                    if (!isEmptyField(FIELD_TYPE)) {
                        ScriptType scriptType = nameToType(getStringValue(FIELD_TYPE));
                        if (scriptType != null) {
                            scriptEnableable = scriptType.isEnableable();
                            scriptEnabledByDefault = scriptType.isEnabledByDefault();
                        }
                    }
                    getField(FIELD_ENABLED).setEnabled(scriptEnableable);
                    setFieldValue(FIELD_ENABLED, scriptEnabledByDefault);
                });
        this.addPadding();
    }

    private List<String> getEngines() {
        ArrayList<String> list = new ArrayList<>();
        list.addAll(extension.getExtScript().getScriptingEngines());
        return list;
    }

    private List<String> getTypes() {
        ArrayList<String> list = new ArrayList<>();
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

    @Override
    public void save() {
        script.setName(this.getStringValue(FIELD_NAME));
        script.setDescription(this.getStringValue(FIELD_DESC));
        script.setType(this.nameToType(this.getStringValue(FIELD_TYPE)));
        script.setLoadOnStart(this.getBoolValue(FIELD_LOAD));
        script.setEnabled(getBoolValue(FIELD_ENABLED));
        script.setEngine(
                extension.getExtScript().getEngineWrapper(this.getStringValue(FIELD_ENGINE)));

        extension.getExtScript().addScript(script);
    }

    @Override
    public String validateFields() {
        if (this.isEmptyField(FIELD_NAME)) {
            return Constant.messages.getString("scripts.dialog.script.error.name");
        }
        if (extension.getExtScript().getScript(this.getStringValue(FIELD_NAME)) != null) {
            return Constant.messages.getString("scripts.dialog.script.error.duplicate");
        }
        return null;
    }

    public void reset(ScriptWrapper script) {
        this.script = script;
        this.setFieldValue(FIELD_FILE, script.getFile().getAbsolutePath());
        this.setFieldValue(FIELD_NAME, script.getFile().getName());
        int dotIndex = script.getFile().getName().lastIndexOf(".");
        if (dotIndex > 0) {
            // Work out the type based on the extension
            String extn = script.getFile().getName().substring(dotIndex + 1);
            String name = extension.getExtScript().getEngineNameForExtension(extn);
            if (name != null) {
                this.setFieldValue(FIELD_ENGINE, name);
            }
        }
        // Use the type from the parent dir, if its a valid one
        String parentDir = script.getFile().getParentFile().getName();
        ScriptType type = extension.getExtScript().getScriptType(parentDir);
        if (type == null) {
            type = extension.getExtScript().getScriptType(ExtensionScript.TYPE_STANDALONE);
        }
        this.setFieldValue(FIELD_TYPE, Constant.messages.getString(type.getI18nKey()));

        this.setFieldValue(FIELD_DESC, "");
    }
}
