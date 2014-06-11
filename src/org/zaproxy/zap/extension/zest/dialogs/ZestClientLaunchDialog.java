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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.mozilla.zest.core.v1.ZestClientLaunch;
import org.mozilla.zest.core.v1.ZestStatement;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestScriptWrapper;
import org.zaproxy.zap.extension.zest.ZestZapUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

public class ZestClientLaunchDialog extends StandardFieldsDialog implements ZestDialog {

	private static final String FIELD_WINDOW_HANDLE = "zest.dialog.client.label.windowHandle"; 
	private static final String FIELD_BROWSER_TYPE = "zest.dialog.client.label.browserType"; 
	private static final String FIELD_URL = "zest.dialog.client.label.url"; 

	private static String BROWSER_TYPE_PREFIX = "zest.dialog.client.browserType.label.";
	private static String[] BROWSER_TYPES = {"firefox", "chrome", "htmlunit", "internetexplorer", "opera", "safari"};
	private static String DEFAULT_BROWSER_TYPE = "firefox";

	private static final long serialVersionUID = 1L;

	private ExtensionZest extension = null;
	private ScriptNode parent = null;
	private ScriptNode child = null;
	private ZestScriptWrapper script = null;
	private ZestStatement request = null;
	private ZestClientLaunch client = null;
	private boolean add = false;

	public ZestClientLaunchDialog(ExtensionZest ext, Frame owner, Dimension dim) {
		super(owner, "zest.dialog.clientLaunch.add.title", dim);
		this.extension = ext;
	}

	public void init (ZestScriptWrapper script, ScriptNode parent, ScriptNode child, 
			ZestStatement req, ZestClientLaunch client, boolean add) {
		this.script = script;
		this.add = add;
		this.parent = parent;
		this.child = child;
		this.request = req;
		this.client = client;

		this.removeAllFields();
		
		if (add) {
			this.setTitle(Constant.messages.getString("zest.dialog.clientLaunch.add.title"));
		} else {
			this.setTitle(Constant.messages.getString("zest.dialog.clientLaunch.edit.title"));
		}

		this.addTextField(FIELD_WINDOW_HANDLE, client.getWindowHandle());
		String browserType = client.getBrowserType();
		if (browserType == null || browserType.length() == 0) {
			browserType = DEFAULT_BROWSER_TYPE;
		}
		this.addComboField(FIELD_BROWSER_TYPE, getBrowserTypes(), 
				Constant.messages.getString(BROWSER_TYPE_PREFIX + browserType));
		this.addTextField(FIELD_URL, client.getUrl());
	}
	
	private List<String> getBrowserTypes() {
		List<String> list = new ArrayList<String>();
		for (String type : BROWSER_TYPES) {
			list.add(Constant.messages.getString(BROWSER_TYPE_PREFIX + type));
		}
		Collections.sort(list);
		return list;
	}

	private String getSelectedBrowserType() {
		String selectedType = this.getStringValue(FIELD_BROWSER_TYPE);
		for (String type : BROWSER_TYPES) {
			if (Constant.messages.getString(BROWSER_TYPE_PREFIX + type).equals(selectedType)) {
				return type;
			}
		}
		return null;
	}


	public void save() {
		client.setWindowHandle(this.getStringValue(FIELD_WINDOW_HANDLE));
		client.setBrowserType(this.getSelectedBrowserType());
		client.setUrl(this.getStringValue(FIELD_URL));

		if (add) {
			if (request == null) {
				extension.addToParent(parent, client);
			} else {
				extension.addAfterRequest(parent, child, request, client);
			}
		} else {
			extension.updated(child);
			extension.display(child, false);
		}
	}

	@Override
	public String validateFields() {
		// Cant validate the url as it may contain tokens
		
		if (! ZestZapUtils.isValidVariableName(this.getStringValue(FIELD_WINDOW_HANDLE))) {
			return Constant.messages.getString("zest.dialog.client.error.windowHandle");
		}

		return null;
	}

	@Override
	public ZestScriptWrapper getScript() {
		return this.script;
	}
	
}
