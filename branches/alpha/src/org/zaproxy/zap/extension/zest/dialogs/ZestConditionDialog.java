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
import java.util.regex.Pattern;

import org.mozilla.zest.core.v1.ZestConditionRegex;
import org.mozilla.zest.core.v1.ZestConditionResponseTime;
import org.mozilla.zest.core.v1.ZestConditionStatusCode;
import org.mozilla.zest.core.v1.ZestConditional;
import org.mozilla.zest.core.v1.ZestStatement;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestNode;
import org.zaproxy.zap.view.StandardFieldsDialog;

public class ZestConditionDialog extends StandardFieldsDialog {

	private static final String FIELD_LOCATION = "zest.dialog.condition.label.location"; 
	private static final String FIELD_REGEX = "zest.dialog.condition.label.regex"; 
	private static final String FIELD_STATUS = "zest.dialog.condition.label.status"; 
	private static final String FIELD_GREATER_THAN = "zest.dialog.condition.label.greaterthan"; 
	private static final String FIELD_RESP_TIME = "zest.dialog.condition.label.resptime";

	private static final long serialVersionUID = 1L;

	private ExtensionZest extension = null;
	private ZestNode parent = null;
	private ZestStatement request = null;
	private ZestConditional condition = null;
	private boolean add = false;

	public ZestConditionDialog(ExtensionZest ext, Frame owner, Dimension dim) {
		super(owner, "zest.dialog.action.add.title", dim);
		this.extension = ext;
	}

	public void init (ZestNode parent, ZestStatement req, ZestConditional condition, boolean add) {
		this.add = add;
		this.parent = parent;
		this.request = req;
		this.condition = condition;

		this.removeAllFields();
		
		if (add) {
			this.setTitle(Constant.messages.getString("zest.dialog.condition.add.title"));
		} else {
			this.setTitle(Constant.messages.getString("zest.dialog.condition.edit.title"));
		}
		
		if (condition instanceof ZestConditionRegex) {
			ZestConditionRegex zc = (ZestConditionRegex)condition;
			this.addComboField(FIELD_LOCATION, new String[]{"HEAD", "BODY"}, zc.getLocation());
			this.addTextField(FIELD_REGEX, zc.getRegex());
			
		} else if (condition instanceof ZestConditionStatusCode) {
			ZestConditionStatusCode zc = (ZestConditionStatusCode)condition;
			this.addComboField(FIELD_STATUS, HttpStatusCode.CODES, zc.getCode());
			
		} else if (condition instanceof ZestConditionResponseTime) {
			ZestConditionResponseTime zc = (ZestConditionResponseTime)condition;
			this.addCheckBoxField(FIELD_GREATER_THAN, zc.isGreaterThan());
			this.addNumberField(FIELD_RESP_TIME, 0, Integer.MAX_VALUE, (int)zc.getTimeInMs());
		}
		this.addPadding();
	}
	
	public void save() {
		if (condition instanceof ZestConditionRegex) {
			ZestConditionRegex zc = (ZestConditionRegex)condition;
			zc.setLocation(this.getStringValue(FIELD_LOCATION));
			zc.setRegex(this.getStringValue(FIELD_REGEX));

		} else if (condition instanceof ZestConditionStatusCode) {
			ZestConditionStatusCode zc = (ZestConditionStatusCode)condition;
			zc.setCode(this.getIntValue(FIELD_STATUS));
			
		} else if (condition instanceof ZestConditionResponseTime) {
			ZestConditionResponseTime zc = (ZestConditionResponseTime)condition;
			zc.setGreaterThan(this.getBoolValue(FIELD_GREATER_THAN));
			zc.setTimeInMs(this.getIntValue(FIELD_RESP_TIME));
		}

		if (add) {
			if (request == null) {
				extension.addToParent(parent, condition);
			} else {
				extension.addAfterRequest(parent, request, condition);
			}
		} else {
			extension.update((ZestStatement)parent.getZestElement(), condition);
		}
	}

	@Override
	public String validateFields() {
		if (condition instanceof ZestConditionRegex) {
			try {
				Pattern.compile(this.getStringValue(FIELD_REGEX));
			} catch (Exception e) {
				return Constant.messages.getString("zest.dialog.condition.error.regex");
			}
		}
		return null;
	}
	
}
