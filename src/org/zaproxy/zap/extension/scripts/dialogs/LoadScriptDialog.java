/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2013 ZAP development team
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0 
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
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.scripts.ExtensionScripts;
import org.zaproxy.zap.extension.scripts.ScriptEngineWrapper;
import org.zaproxy.zap.extension.scripts.ScriptWrapper;
import org.zaproxy.zap.view.StandardFieldsDialog;

public class LoadScriptDialog extends StandardFieldsDialog {

	private static final String FIELD_FILE = "scripts.dialog.script.label.file"; 
	private static final String FIELD_NAME = "scripts.dialog.script.label.name"; 
	private static final String FIELD_ENGINE = "scripts.dialog.script.label.engine"; 
	private static final String FIELD_DESC = "scripts.dialog.script.label.desc";
	private static final String FIELD_TYPE = "scripts.dialog.script.label.type";
	private static final String FIELD_LOAD = "scripts.dialog.script.label.load";

	private static final String TYPE_PREFIX = "scripts.type.";

	private static final long serialVersionUID = 1L;

	private ExtensionScripts extension = null;
	private ScriptWrapper script = null;
	
	public LoadScriptDialog(ExtensionScripts ext, Frame owner, Dimension dim) {
		super(owner, "scripts.dialog.script.load.title", dim);
		this.extension = ext;
		init();
	}

	private void init () {
		// TODO this should really be a load file 
		this.setTitle(Constant.messages.getString("scripts.dialog.script.load.title"));
		this.addTextField(FIELD_NAME, "");
		this.addComboField(FIELD_ENGINE, extension.getScriptingEngines(), "");
		this.addComboField(FIELD_TYPE, this.getTypes(), "");
		this.addMultilineField(FIELD_DESC, "");
		this.addCheckBoxField(FIELD_LOAD, false);
		this.addFieldListener(FIELD_ENGINE, new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				// Change the types based on which engine is selected
				ScriptEngineWrapper sew = extension.getEngineWrapper(getStringValue(FIELD_ENGINE));
				if (sew.isRawEngine()) {
					// Raw engines can only support targeted scripts as there will be no templates
					setComboFields(FIELD_TYPE, 
							new String[]{typeToName(ScriptWrapper.Type.STANDALONE)}, 
							typeToName(ScriptWrapper.Type.STANDALONE));
				} else {
					setComboFields(FIELD_ENGINE, extension.getScriptingEngines(), "");
				}
			}});

		this.addPadding();
	}
	
	private String typeToName (ScriptWrapper.Type type) {
		return Constant.messages.getString(TYPE_PREFIX + type.name().toLowerCase());
	}
	
	private List<String> getTypes() {
		ArrayList<String> list = new ArrayList<String>();
		for (ScriptWrapper.Type type : ScriptWrapper.Type.values()) {
			list.add(this.typeToName(type));
		}
		return list;
	}
	
	private ScriptWrapper.Type nameToType (String name) {
		for (ScriptWrapper.Type type : ScriptWrapper.Type.values()) {
			if (Constant.messages.getString(TYPE_PREFIX + type.name().toLowerCase()).equals(name)) {
				return type;
			}
		}
		return null;
	}
	
	public void save() {
		script.setName(this.getStringValue(FIELD_NAME));
		script.setDescription(this.getStringValue(FIELD_DESC));
		script.setType(this.nameToType(this.getStringValue(FIELD_TYPE)));
		script.setLoadOnStart(this.getBoolValue(FIELD_LOAD));
		script.setType(this.nameToType(this.getStringValue(FIELD_TYPE)));
		script.setEngine(extension.getEngineWrapper(this.getStringValue(FIELD_ENGINE)));

		extension.addScript(script);
	}

	@Override
	public String validateFields() {
		if (this.isEmptyField(FIELD_NAME)) {
			return Constant.messages.getString("scripts.dialog.script.error.name");
		}
		if (extension.getScript(this.getStringValue(FIELD_NAME)) != null) {
			return Constant.messages.getString("scripts.dialog.script.error.duplicate");
		}
		return null;
	}

	public void reset(ScriptWrapper script) {
		this.script = script;
		this.setFieldValue(FIELD_FILE, script.getFile().getAbsolutePath());
		this.setFieldValue(FIELD_NAME, script.getFile().getName());
		this.setFieldValue(FIELD_DESC, "");
	}
	
}
