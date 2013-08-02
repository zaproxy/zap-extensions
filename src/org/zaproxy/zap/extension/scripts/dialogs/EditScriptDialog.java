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

import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.scripts.ExtensionScripts;
import org.zaproxy.zap.view.StandardFieldsDialog;

public class EditScriptDialog extends StandardFieldsDialog {

	private static final String FIELD_NAME = "scripts.dialog.script.label.name"; 
	private static final String FIELD_DESC = "scripts.dialog.script.label.desc";
	private static final String FIELD_LOAD = "scripts.dialog.script.label.load";

	private static final long serialVersionUID = 1L;

	private ExtensionScripts extension = null;
	private ScriptWrapper script = null;
	
	public EditScriptDialog(ExtensionScripts ext, Frame owner, Dimension dim) {
		super(owner, "scripts.dialog.script.edit.title", dim);
		this.extension = ext;
	}

	public void init (ScriptWrapper script) {
		this.script = script;
		this.setTitle(Constant.messages.getString("scripts.dialog.script.edit.title"));
		if (script != null) {
			this.removeAllFields();
			this.addTextField(FIELD_NAME, script.getName());
			this.addMultilineField(FIELD_DESC, script.getDescription());
			this.addCheckBoxField(FIELD_LOAD, script.isLoadOnStart());
		}

		this.addPadding();
	}
	
	public void save() {
		script.setName(this.getStringValue(FIELD_NAME));
		script.setDescription(this.getStringValue(FIELD_DESC));
		script.setLoadOnStart(this.getBoolValue(FIELD_LOAD));
		extension.getExtScript().setChanged(script, true);
	}

	@Override
	public String validateFields() {
		if (this.isEmptyField(FIELD_NAME)) {
			return Constant.messages.getString("scripts.dialog.script.error.name");
		}
		if (!this.getStringValue(FIELD_NAME).equals(script.getName()) && 
				extension.getExtScript().getScript(this.getStringValue(FIELD_NAME)) != null) {
			// Trying to change the name to one used by another script
			return Constant.messages.getString("scripts.dialog.script.error.duplicate");
		}
		return null;
	}
}
