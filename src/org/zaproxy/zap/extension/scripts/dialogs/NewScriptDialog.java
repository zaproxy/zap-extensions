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
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptEngineWrapper;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.scripts.ExtensionScripts;
import org.zaproxy.zap.view.StandardFieldsDialog;

public class NewScriptDialog extends StandardFieldsDialog {

	private static final String FIELD_NAME = "scripts.dialog.script.label.name"; 
	private static final String FIELD_ENGINE = "scripts.dialog.script.label.engine"; 
	private static final String FIELD_DESC = "scripts.dialog.script.label.desc";
	private static final String FIELD_TYPE = "scripts.dialog.script.label.type";
	private static final String FIELD_LOAD = "scripts.dialog.script.label.load";

	private static final long serialVersionUID = 1L;

	private ExtensionScripts extension = null;
	
	public NewScriptDialog(ExtensionScripts ext, Frame owner, Dimension dim) {
		super(owner, "scripts.dialog.script.new.title", dim);
		this.extension = ext;
		init();
	}

	private void init () {
		this.setTitle(Constant.messages.getString("scripts.dialog.script.new.title"));
		this.addTextField(FIELD_NAME, "");
		this.addComboField(FIELD_ENGINE, extension.getExtScript().getScriptingEngines(), "");
		this.addComboField(FIELD_TYPE, this.getTypes(), "");
		this.addMultilineField(FIELD_DESC, "");
		this.addCheckBoxField(FIELD_LOAD, false);
		this.addFieldListener(FIELD_ENGINE, new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				// Change the types based on which engine is selected
				ScriptEngineWrapper sew = extension.getExtScript().getEngineWrapper(getStringValue(FIELD_ENGINE));
				if (sew.isRawEngine()) {
					// Raw engines can only support targeted scripts as there will be no templates
					ScriptType tsa = extension.getExtScript().getScriptType(ExtensionScript.TYPE_STANDALONE);
					setComboFields(FIELD_TYPE, 
							new String[]{Constant.messages.getString(tsa.getI18nKey())}, 
							Constant.messages.getString(tsa.getI18nKey()));
				} else {
					setComboFields(FIELD_TYPE, getTypes(), "");
				}
			}});

		this.addPadding();
	}
	
	private List<String> getTypes() {
		ArrayList<String> list = new ArrayList<String>();
		for (ScriptType type : extension.getExtScript().getScriptTypes()) {
			list.add(Constant.messages.getString(type.getI18nKey()));
		}
		return list;
	}
	
	private ScriptType nameToType (String name) {
		for (ScriptType type : extension.getExtScript().getScriptTypes()) {
			if (Constant.messages.getString(type.getI18nKey()).equals(name)) {
				return type;
			}
		}
		return null;
	}
	
	public void save() {
		ScriptWrapper script = new ScriptWrapper();
		script.setName(this.getStringValue(FIELD_NAME));
		script.setDescription(this.getStringValue(FIELD_DESC));
		script.setType(this.nameToType(this.getStringValue(FIELD_TYPE)));
		script.setLoadOnStart(this.getBoolValue(FIELD_LOAD));
		script.setType(this.nameToType(this.getStringValue(FIELD_TYPE)));

		ScriptEngineWrapper ew = extension.getExtScript().getEngineWrapper(this.getStringValue(FIELD_ENGINE));
		script.setEngine(ew);
		script.setContents(ew.getTemplate(script.getType().getName()));
		
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

	public void reset() {
		this.setFieldValue(FIELD_NAME, "");
		this.setFieldValue(FIELD_DESC, "");
	}
	
}
