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
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import org.mozilla.zest.core.v1.ZestAssignFieldValue;
import org.mozilla.zest.core.v1.ZestAssignRandomInteger;
import org.mozilla.zest.core.v1.ZestAssignRegexDelimiters;
import org.mozilla.zest.core.v1.ZestAssignStringDelimiters;
import org.mozilla.zest.core.v1.ZestAssignment;
import org.mozilla.zest.core.v1.ZestFieldDefinition;
import org.mozilla.zest.core.v1.ZestRequest;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.view.StandardFieldsDialog;

public class ZestAssignmentDialog extends StandardFieldsDialog {

	private static final String FIELD_VARIABLE = "zest.dialog.assign.label.variable";
	private static final String FIELD_MIN_INT = "zest.dialog.assign.label.minint";
	private static final String FIELD_MAX_INT = "zest.dialog.assign.label.maxint";
	private static final String FIELD_REPLACE_FORM = "zest.dialog.assign.label.repform";
	private static final String FIELD_REPLACE_FIELD = "zest.dialog.assign.label.repfield";
	private static final String FIELD_LOCATION = "zest.dialog.assign.label.location"; 
	private static final String FIELD_REGEX_PREFIX = "zest.dialog.assign.label.rgxprefix";
	private static final String FIELD_REGEX_POSTFIX = "zest.dialog.assign.label.rgxpostfix";
	private static final String FIELD_STRING_PREFIX = "zest.dialog.assign.label.strprefix";
	private static final String FIELD_STRING_POSTFIX = "zest.dialog.assign.label.strpostfix";

	private static final long serialVersionUID = 1L;

	private ExtensionZest extension = null;
	private ScriptNode parent = null;
	private ScriptNode child = null;
	private ZestRequest request = null;
	private ZestAssignment assign = null;
	private boolean add = false;

	public ZestAssignmentDialog(ExtensionZest ext, Frame owner, Dimension dim) {
		super(owner, "zest.dialog.assign.add.title", dim);
		this.extension = ext;
	}

	public void init (ScriptNode parent, ScriptNode child, ZestRequest req, ZestAssignment assign, boolean add) {
		this.add = add;
		this.parent = parent;
		this.child = child;
		this.request = req;
		this.assign = assign;

		this.removeAllFields();
		
		if (add) {
			this.setTitle(Constant.messages.getString("zest.dialog.assign.add.title"));
		} else {
			this.setTitle(Constant.messages.getString("zest.dialog.assign.edit.title"));
		}
		
		this.addTextField(FIELD_VARIABLE, assign.getVariableName());

		if (assign instanceof ZestAssignFieldValue) {
			ZestAssignFieldValue za = (ZestAssignFieldValue) assign;
			if (za.getFieldDefinition() == null) {
				za.setFieldDefinition(new ZestFieldDefinition());
			}
			this.addComboField(FIELD_REPLACE_FORM, new String [] {}, "");
			this.addFieldListener(FIELD_REPLACE_FORM, new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					initFieldField(null);
				}});

			this.addComboField(FIELD_REPLACE_FIELD, new String [] {}, "");
			
			// Set default values
			initFormField(Integer.toString(za.getFieldDefinition().getFormIndex()));
			initFieldField(za.getFieldDefinition().getFieldName());

		} else if (assign instanceof ZestAssignRandomInteger) {
			ZestAssignRandomInteger za = (ZestAssignRandomInteger) assign;
			this.addNumberField(FIELD_MIN_INT, 0, Integer.MAX_VALUE, za.getMinInt());
			this.addNumberField(FIELD_MAX_INT, 0, Integer.MAX_VALUE, za.getMaxInt());

		} else if (assign instanceof ZestAssignRegexDelimiters) {
			ZestAssignRegexDelimiters za = (ZestAssignRegexDelimiters) assign;
			this.addComboField(FIELD_LOCATION, new String[]{"HEAD", "BODY"}, za.getLocation());
			this.addTextField(FIELD_REGEX_PREFIX, za.getPrefix());
			this.addTextField(FIELD_REGEX_POSTFIX, za.getPostfix());

		} else if (assign instanceof ZestAssignStringDelimiters) {
			ZestAssignStringDelimiters za = (ZestAssignStringDelimiters) assign;
			this.addComboField(FIELD_LOCATION, new String[]{"HEAD", "BODY"}, za.getLocation());
			this.addTextField(FIELD_STRING_PREFIX, za.getPrefix());
			this.addTextField(FIELD_STRING_POSTFIX, za.getPostfix());
		}
		this.addPadding();
	}
	
	private void initFormField(String value) {
		List <String> list = new ArrayList<String>();
		if (request != null && request.getResponse() != null) {
			List<String> forms = org.mozilla.zest.impl.ZestUtils.getForms(request.getResponse());
			for (String form : forms) {
				list.add(form);
			}
			this.setComboFields(FIELD_REPLACE_FORM, list, value);
			initFieldField(null);
		}
	}

	private void initFieldField(String value) {
		int formIndex = -1;
		String formStr = this.getStringValue(FIELD_REPLACE_FORM);
		if (formStr != null && formStr.length() > 0) {
			formIndex = Integer.parseInt(formStr);
		}
		
		if (formIndex >= 0) {
			// TODO support form names too
			if (request != null && request.getResponse() != null) {
				List<String> fields = org.mozilla.zest.impl.ZestUtils.getFields(request.getResponse(), formIndex);
				this.setComboFields(FIELD_REPLACE_FIELD, fields, value);
			}
		}

	}

	public void save() {
		
		assign.setVariableName(this.getStringValue(FIELD_VARIABLE));
		
		if (assign instanceof ZestAssignFieldValue) {
			ZestAssignFieldValue za = (ZestAssignFieldValue) assign;
			if (za.getFieldDefinition() == null) {
				za.setFieldDefinition(new ZestFieldDefinition());
			}
			za.getFieldDefinition().setFormIndex(Integer.parseInt(this.getStringValue(FIELD_REPLACE_FORM)));
			za.getFieldDefinition().setFieldName(this.getStringValue(FIELD_REPLACE_FIELD));

		} else if (assign instanceof ZestAssignRandomInteger) {
			ZestAssignRandomInteger za = (ZestAssignRandomInteger) assign;
			za.setMinInt(this.getIntValue(FIELD_MIN_INT));
			za.setMaxInt(this.getIntValue(FIELD_MAX_INT));

		} else if (assign instanceof ZestAssignRegexDelimiters) {
			ZestAssignRegexDelimiters za = (ZestAssignRegexDelimiters) assign;
			za.setLocation(this.getStringValue(FIELD_LOCATION));
			za.setPrefix(this.getStringValue(FIELD_REGEX_PREFIX));
			za.setPostfix(this.getStringValue(FIELD_REGEX_POSTFIX));

		} else if (assign instanceof ZestAssignStringDelimiters) {
			ZestAssignStringDelimiters za = (ZestAssignStringDelimiters) assign;
			za.setLocation(this.getStringValue(FIELD_LOCATION));
			za.setPrefix(this.getStringValue(FIELD_STRING_PREFIX));
			za.setPostfix(this.getStringValue(FIELD_STRING_POSTFIX));
		}

		if (add) {
			if (request == null) {
				extension.addToParent(parent, assign);
			} else {
				extension.addAfterRequest(parent, child, request, assign);
			}
		} else {
			extension.updated(child);
			extension.display(child, false);
		}
	}
	
	@Override
	public String validateFields() {
		if (this.isEmptyField(FIELD_VARIABLE)) {
			return Constant.messages.getString("zest.dialog.assign.error.variable");
		}
		if (assign instanceof ZestAssignFieldValue) {
			if (this.isEmptyField(FIELD_REPLACE_FORM)) {
				return Constant.messages.getString("zest.dialog.assign.error.repform");
			}
			if (this.isEmptyField(FIELD_REPLACE_FIELD)) {
				return Constant.messages.getString("zest.dialog.assign.error.repfield");
			}

		} else if (assign instanceof ZestAssignRandomInteger) {
			if (this.getIntValue(FIELD_MIN_INT) >= this.getIntValue(FIELD_MAX_INT)) {
				return Constant.messages.getString("zest.dialog.assign.error.minint");
			}
			
		} else if (assign instanceof ZestAssignRegexDelimiters) {
			if (this.isEmptyField(FIELD_REGEX_PREFIX)) {
				return Constant.messages.getString("zest.dialog.assign.error.regexprefix");
			}
			try {
				Pattern.compile(this.getStringValue(FIELD_REGEX_PREFIX));
			} catch (Exception e) {
				return Constant.messages.getString("zest.dialog.assign.error.regexprefix");
			}

			if (this.isEmptyField(FIELD_REGEX_POSTFIX)) {
				return Constant.messages.getString("zest.dialog.assign.error.regexpostfix");
			}
			try {
				Pattern.compile(this.getStringValue(FIELD_REGEX_POSTFIX));
			} catch (Exception e) {
				return Constant.messages.getString("zest.dialog.assign.error.regexpostfix");
			}

		} else if (assign instanceof ZestAssignStringDelimiters) {
			if (this.isEmptyField(FIELD_STRING_PREFIX)) {
				return Constant.messages.getString("zest.dialog.assign.error.strprefix");
			}

			if (this.isEmptyField(FIELD_STRING_POSTFIX)) {
				return Constant.messages.getString("zest.dialog.assign.error.strpostfix");
			}
		}
		return null;
	}
	
}
