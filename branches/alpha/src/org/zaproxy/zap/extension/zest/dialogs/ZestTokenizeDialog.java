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
package org.zaproxy.zap.extension.zest.dialogs;

import java.awt.Dimension;
import java.awt.Frame;

import org.mozilla.zest.core.v1.ZestRequest;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestScriptWrapper;
import org.zaproxy.zap.view.StandardFieldsDialog;

public class ZestTokenizeDialog extends StandardFieldsDialog {

	private static final String FIELD_REPLACE_STRING = "zest.dialog.token.label.repstring"; 
	private static final String FIELD_TOKEN = "zest.dialog.token.label.token"; 
	private static final String FIELD_IN_CURRENT = "zest.dialog.redact.label.current"; 
	private static final String FIELD_IN_ADDED = "zest.dialog.redact.label.added"; 

	private static final long serialVersionUID = 1L;

	private ExtensionZest extension = null;
	private ZestScriptWrapper script= null;
	private ZestRequest request = null;
	private boolean replaceInCurrent = true;
	private boolean replaceInAdded = true;

	public ZestTokenizeDialog(ExtensionZest ext, Frame owner, Dimension dim) {
		super(owner, "zest.dialog.token.title", dim);
		this.extension = ext;
	}

	public void init (ZestScriptWrapper script, ZestRequest request, String replace) {
		this.script = script;
		this.request = request;

		this.removeAllFields();

		this.addTextField(FIELD_REPLACE_STRING, replace);
		this.addTextField(FIELD_TOKEN, "");
		this.addCheckBoxField(FIELD_IN_CURRENT, this.replaceInCurrent);
		this.addCheckBoxField(FIELD_IN_ADDED, this.replaceInAdded);
		this.addPadding();
	}
	

	public void save() {
		this.extension.setToken(script, request, this.getStringValue(FIELD_REPLACE_STRING),
				this.getStringValue(FIELD_TOKEN), this.getBoolValue(FIELD_IN_CURRENT), this.getBoolValue(FIELD_IN_ADDED));
	}

	@Override
	public String validateFields() {
		if (this.isEmptyField(FIELD_REPLACE_STRING)) {
			return Constant.messages.getString("zest.dialog.token.error.repstring");
		}
		if (this.isEmptyField(FIELD_TOKEN)) {
			return Constant.messages.getString("zest.dialog.token.error.token");
		}
		return null;
	}
	
}
