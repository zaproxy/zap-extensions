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

import org.mozilla.zest.core.v1.ZestAssertBodyRegex;
import org.mozilla.zest.core.v1.ZestAssertHeaderRegex;
import org.mozilla.zest.core.v1.ZestAssertLength;
import org.mozilla.zest.core.v1.ZestAssertStatusCode;
import org.mozilla.zest.core.v1.ZestAssertion;
import org.mozilla.zest.core.v1.ZestRequest;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.view.StandardFieldsDialog;

public class ZestAssertionsDialog extends StandardFieldsDialog {

	private static final String FIELD_LENGTH = "zest.dialog.assert.label.length"; 
	private static final String FIELD_APPROX = "zest.dialog.assert.label.approx"; 
	private static final String FIELD_STATUS = "zest.dialog.assert.label.status"; 
	private static final String FIELD_REGEX = "zest.dialog.assert.label.regex"; 
	private static final String FIELD_INVERSE = "zest.dialog.assert.label.inverse"; 

	private static final long serialVersionUID = 1L;

	private ExtensionZest extension = null;
	private ZestRequest request = null;
	private ZestAssertion assertion = null;
	private boolean add = false;

	public ZestAssertionsDialog(ExtensionZest ext, Frame owner, Dimension dim) {
		super(owner, "zest.dialog.assert.add.title", dim);
		this.extension = ext;
	}

	public void init (ZestRequest req, ZestAssertion assertion, boolean add) {
		this.add = add;
		this.request = req;
		this.assertion = assertion;

		this.removeAllFields();
		
		if (add) {
			this.setTitle(Constant.messages.getString("zest.dialog.assert.add.title"));
		} else {
			this.setTitle(Constant.messages.getString("zest.dialog.assert.edit.title"));
		}

		if (assertion instanceof ZestAssertLength) {
			ZestAssertLength za = (ZestAssertLength) assertion;
			this.addNumberField(FIELD_LENGTH, 0, Integer.MAX_VALUE, za.getLength());
			this.addNumberField(FIELD_APPROX, 0, 100, za.getApprox());
			
		} else if (assertion instanceof ZestAssertStatusCode) {
			ZestAssertStatusCode za = (ZestAssertStatusCode) assertion;
			this.addComboField(FIELD_STATUS, HttpStatusCode.CODES, za.getCode());
			
		} else if (assertion instanceof ZestAssertHeaderRegex) {
			ZestAssertHeaderRegex za = (ZestAssertHeaderRegex) assertion;
			this.addTextField(FIELD_REGEX, za.getRegex());
			this.addCheckBoxField(FIELD_INVERSE, za.isInverse());
			
		} else if (assertion instanceof ZestAssertBodyRegex) {
			ZestAssertBodyRegex za = (ZestAssertBodyRegex) assertion;
			this.addTextField(FIELD_REGEX, za.getRegex());
			this.addCheckBoxField(FIELD_INVERSE, za.isInverse());
		}
		this.addPadding();
	}
	

	public void save() {
		if (assertion instanceof ZestAssertLength) {
			ZestAssertLength za = (ZestAssertLength) assertion;
			za.setLength(this.getIntValue(FIELD_LENGTH));
			za.setApprox(this.getIntValue(FIELD_APPROX));
			
		} else if (assertion instanceof ZestAssertStatusCode) {
			ZestAssertStatusCode za = (ZestAssertStatusCode) assertion;
			za.setCode(this.getIntValue(FIELD_STATUS));
			
		} else if (assertion instanceof ZestAssertHeaderRegex) {
			ZestAssertHeaderRegex za = (ZestAssertHeaderRegex) assertion;
			za.setRegex(this.getStringValue(FIELD_REGEX));
			za.setInverse(this.getBoolValue(FIELD_INVERSE));
			
		} else if (assertion instanceof ZestAssertBodyRegex) {
			ZestAssertBodyRegex za = (ZestAssertBodyRegex) assertion;
			za.setRegex(this.getStringValue(FIELD_REGEX));
			za.setInverse(this.getBoolValue(FIELD_INVERSE));
		}

		if (add) {
			extension.addToRequest(request, assertion);
		} else {
			extension.update(request, assertion);
		}
	}

	@Override
	public String validateFields() {
		if (assertion instanceof ZestAssertLength) {
			// Nothing to do
			
		} else if (assertion instanceof ZestAssertStatusCode) {
			// Nothing to do
			
		} else if (assertion instanceof ZestAssertHeaderRegex) {
			try {
				Pattern.compile(this.getStringValue(FIELD_REGEX));
			} catch (Exception e) {
				return Constant.messages.getString("zest.dialog.assert.error.regex");
			}
			
		} else if (assertion instanceof ZestAssertBodyRegex) {
			try {
				Pattern.compile(this.getStringValue(FIELD_REGEX));
			} catch (Exception e) {
				return Constant.messages.getString("zest.dialog.assert.error.regex");
			}
		}
		return null;
	}
	
}
