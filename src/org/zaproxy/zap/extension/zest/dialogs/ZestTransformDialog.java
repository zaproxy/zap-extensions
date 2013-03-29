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

import org.mozilla.zest.core.v1.ZestContainer;
import org.mozilla.zest.core.v1.ZestFieldDefinition;
import org.mozilla.zest.core.v1.ZestRequest;
import org.mozilla.zest.core.v1.ZestScript;
import org.mozilla.zest.core.v1.ZestStatement;
import org.mozilla.zest.core.v1.ZestTransformFieldReplace;
import org.mozilla.zest.core.v1.ZestTransformRndIntReplace;
import org.mozilla.zest.core.v1.ZestTransformation;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestNode;
import org.zaproxy.zap.view.StandardFieldsDialog;

public class ZestTransformDialog extends StandardFieldsDialog {

	private static final String FIELD_REQ_STRING = "zest.dialog.transform.label.reqstring";
	private static final String FIELD_MIN_INT = "zest.dialog.transform.label.minint";
	private static final String FIELD_MAX_INT = "zest.dialog.transform.label.maxint";
	private static final String FIELD_REPLACE_INDEX = "zest.dialog.transform.label.repindex";
	private static final String FIELD_REPLACE_FORM = "zest.dialog.transform.label.repform";
	private static final String FIELD_REPLACE_FIELD = "zest.dialog.transform.label.repfield";

	private static final long serialVersionUID = 1L;

	private ExtensionZest extension = null;
	private ZestNode reqNode = null;
	private ZestScript script = null;
	private ZestRequest request = null;
	private ZestTransformation transformation = null;
	private boolean add = false;

	public ZestTransformDialog(ExtensionZest ext, Frame owner, Dimension dim) {
		super(owner, "zest.dialog.transform.add.title", dim);
		this.extension = ext;
	}

	public void init (ZestScript script, ZestNode reqNode, ZestTransformation transformation, boolean add) {
		this.add = add;
		this.script = script;
		this.reqNode = reqNode;
		this.request = (ZestRequest) reqNode.getZestElement();
		this.transformation = transformation;

		this.removeAllFields();
		
		if (add) {
			this.setTitle(Constant.messages.getString("zest.dialog.transform.add.title"));
		} else {
			this.setTitle(Constant.messages.getString("zest.dialog.transform.edit.title"));
		}

		if (transformation instanceof ZestTransformFieldReplace) {
			ZestTransformFieldReplace za = (ZestTransformFieldReplace) transformation;
			if (za.getFieldDefinition() == null) {
				za.setFieldDefinition(new ZestFieldDefinition());
			}
			List<String> list = this.getRequestList(this.reqNode.getParent(), this.request, null);
			this.addTextField(FIELD_REQ_STRING, za.getRequestString());
			this.addComboField(FIELD_REPLACE_INDEX, list, this.getSelectedRequest(list, za.getFieldDefinition().getRequestId()));
			this.addFieldListener(FIELD_REPLACE_INDEX, new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					initFormField(null);
				}});
			
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

		} else if (transformation instanceof ZestTransformRndIntReplace) {
			ZestTransformRndIntReplace za = (ZestTransformRndIntReplace) transformation;
			this.addTextField(FIELD_REQ_STRING, za.getRequestString());
			this.addNumberField(FIELD_MIN_INT, 0, Integer.MAX_VALUE, za.getMinInt());
			this.addNumberField(FIELD_MAX_INT, 0, Integer.MAX_VALUE, za.getMaxInt());
		}
		this.addPadding();
	}
	
	private void initFormField(String value) {
		int reqIndex = this.getRequestFieldIndex();
		
		if (reqIndex >= 0) {
			ZestStatement stmt = this.script.getStatement(reqIndex);
			if (stmt instanceof ZestRequest) {
				ZestRequest req = (ZestRequest)stmt;
				List <String> list = new ArrayList<String>();
				if (req != null && req.getResponse() != null) {
					List<String> forms = org.mozilla.zest.impl.ZestUtils.getForms(req.getResponse());
					for (String form : forms) {
						list.add(form);
					}
					this.setComboFields(FIELD_REPLACE_FORM, list, value);
					initFieldField(null);
				}
			}
		}
	}

	private void initFieldField(String value) {
		int reqIndex = this.getRequestFieldIndex();
		int formIndex = -1;
		String formStr = this.getStringValue(FIELD_REPLACE_FORM);
		if (formStr != null && formStr.length() > 0) {
			formIndex = Integer.parseInt(formStr);
		}
		
		if (reqIndex >= 0 && formIndex >= 0) {
			// TODO support form names too
			ZestStatement stmt = this.script.getStatement(reqIndex);
			if (stmt instanceof ZestRequest) {
				ZestRequest req = (ZestRequest)stmt;
				if (req != null && req.getResponse() != null) {
					List<String> fields = org.mozilla.zest.impl.ZestUtils.getFields(req.getResponse(), formIndex);
					this.setComboFields(FIELD_REPLACE_FIELD, fields, value);
				}
			}
		}

	}

	private List<String> getRequestList(ZestNode parent, ZestStatement child, List <String> list) {
		if (list == null) {
			list = new ArrayList<String>();
		}
		// Loop up through parent nodes
		if (parent.getZestElement() instanceof ZestContainer) {
			ZestContainer cont = (ZestContainer) parent.getZestElement();
			while (child != null) {
				if (child instanceof ZestRequest) {
					ZestRequest r = (ZestRequest) child;
					list.add(r.getIndex() + ":" + r.getMethod() + " " + r.getUrl().toString());
				}
				child = cont.getChildBefore(child);
			}
		} 
		return list;
	}
	
	private String getSelectedRequest(List<String> list, int index) {
		for (String str: list) {
			if (str.startsWith(Integer.toString(index) + ":")) {
				return str;
			}
		}
		return null;
	}
	
	private int getRequestFieldIndex() {
		String str = this.getStringValue(FIELD_REPLACE_INDEX);
		if (str != null && str.indexOf(":") > 0) {
			return Integer.parseInt(str.substring(0, str.indexOf(":")));
		}
		return -1;
	}

	public void save() {
		if (transformation instanceof ZestTransformFieldReplace) {
			ZestTransformFieldReplace za = (ZestTransformFieldReplace) transformation;
			za.setRequestString(this.getStringValue(FIELD_REQ_STRING));
			
			if (za.getFieldDefinition() == null) {
				za.setFieldDefinition(new ZestFieldDefinition());
			}
			za.getFieldDefinition().setRequestId(this.getRequestFieldIndex());
			za.getFieldDefinition().setFormIndex(Integer.parseInt(this.getStringValue(FIELD_REPLACE_FORM)));
			za.getFieldDefinition().setFieldName(this.getStringValue(FIELD_REPLACE_FIELD));

		} else if (transformation instanceof ZestTransformRndIntReplace) {
			ZestTransformRndIntReplace za = (ZestTransformRndIntReplace) transformation;
			za.setRequestString(this.getStringValue(FIELD_REQ_STRING));
			za.setMinInt(this.getIntValue(FIELD_MIN_INT));
			za.setMaxInt(this.getIntValue(FIELD_MAX_INT));
		}

		if (add) {
			extension.addToRequest(request, transformation);
		} else {
			extension.update(request, transformation);
		}
	}
	
	@Override
	public String validateFields() {
		if (transformation instanceof ZestTransformFieldReplace) {
			if (this.isEmptyField(FIELD_REQ_STRING)) {
				return Constant.messages.getString("zest.dialog.transform.error.reqstring");
			}
			if (this.request.getData().indexOf(this.getStringValue(FIELD_REQ_STRING)) < 0) {
				return Constant.messages.getString("zest.dialog.transform.error.reqstring");
			}
			if (this.isEmptyField(FIELD_REPLACE_FORM)) {
				return Constant.messages.getString("zest.dialog.transform.error.repform");
			}
			if (this.isEmptyField(FIELD_REPLACE_FIELD)) {
				return Constant.messages.getString("zest.dialog.transform.error.repfield");
			}

		} else if (transformation instanceof ZestTransformRndIntReplace) {
			if (this.isEmptyField(FIELD_REQ_STRING)) {
				return Constant.messages.getString("zest.dialog.transform.error.reqstring");
			}
			if (this.request.getData().indexOf(this.getStringValue(FIELD_REQ_STRING)) < 0) {
				return Constant.messages.getString("zest.dialog.transform.error.reqstring");
			}
			if (this.getIntValue(FIELD_MIN_INT) >= this.getIntValue(FIELD_MAX_INT)) {
				return Constant.messages.getString("zest.dialog.transform.error.minint");
			}
			
		}
		return null;
	}
	
}
