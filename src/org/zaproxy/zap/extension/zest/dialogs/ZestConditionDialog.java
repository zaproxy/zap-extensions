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
import java.util.regex.Pattern;

import org.mozilla.zest.core.v1.ZestConditional;
import org.mozilla.zest.core.v1.ZestExpressionEquals;
import org.mozilla.zest.core.v1.ZestExpressionLength;
import org.mozilla.zest.core.v1.ZestExpressionRegex;
import org.mozilla.zest.core.v1.ZestExpressionResponseTime;
import org.mozilla.zest.core.v1.ZestExpressionStatusCode;
import org.mozilla.zest.core.v1.ZestExpressionURL;
import org.mozilla.zest.core.v1.ZestScript;
import org.mozilla.zest.core.v1.ZestStatement;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.view.StandardFieldsDialog;

public class ZestConditionDialog extends StandardFieldsDialog {

	private static final String FIELD_REGEX = "zest.dialog.condition.label.regex";
	private static final String FIELD_STATUS = "zest.dialog.condition.label.status";
	private static final String FIELD_INVERSE = "zest.dialog.assert.label.inverse";
	private static final String FIELD_GREATER_THAN = "zest.dialog.condition.label.greaterthan";
	private static final String FIELD_RESP_TIME = "zest.dialog.condition.label.resptime";
	private static final String FIELD_INC_REGEXS = "zest.dialog.condition.label.incregexes";
	private static final String FIELD_EXC_REGEXS = "zest.dialog.condition.label.excregexes";
	private static final String FIELD_VARIABLE = "zest.dialog.condition.label.variable";
	private static final String FIELD_VALUE = "zest.dialog.condition.label.value";
	private static final String FIELD_EXACT = "zest.dialog.condition.label.exact"; 
	private static final String FIELD_LENGTH = "zest.dialog.condition.label.length"; 
	private static final String FIELD_APPROX = "zest.dialog.condition.label.approx"; 

	private static final long serialVersionUID = 1L;

	private ExtensionZest extension = null;
	private ZestScript script = null;
	private ScriptNode parent = null;
	private List<ScriptNode> children = null;
	private ZestStatement request = null;
	private ZestConditional condition = null;
	private boolean add = false;
	private boolean surround = false;

	public ZestConditionDialog(ExtensionZest ext, Frame owner, Dimension dim) {
		super(owner, "zest.dialog.condition.add.title", dim);
		this.extension = ext;
	}

	public void init(ZestScript script, ScriptNode parent, List<ScriptNode> children,
			ZestStatement req, ZestConditional condition, boolean add,
			boolean surround) {
		this.script = script;
		this.add = add;
		this.parent = parent;
		this.children = children;
		this.request = req;
		this.condition = condition;
		this.surround = surround;

		this.removeAllFields();

		if (add) {
			this.setTitle(Constant.messages
					.getString("zest.dialog.condition.add.title"));
		} else {
			this.setTitle(Constant.messages
					.getString("zest.dialog.condition.edit.title"));
		}

		if (condition.getRootExpression() instanceof ZestExpressionRegex) {
			ZestExpressionRegex za = (ZestExpressionRegex) condition.getRootExpression();
			this.addComboField(FIELD_VARIABLE, this.getVariableNames(), za.getVariableName());
			this.addTextField(FIELD_REGEX, za.getRegex());
			this.addCheckBoxField(FIELD_EXACT, za.isCaseExact());
			this.addCheckBoxField(FIELD_INVERSE, za.isInverse());

		} else if (condition.getRootExpression() instanceof ZestExpressionEquals) {
			ZestExpressionEquals za = (ZestExpressionEquals) condition.getRootExpression();
			this.addComboField(FIELD_VARIABLE, this.getVariableNames(), za.getVariableName());
			this.addTextField(FIELD_VALUE, za.getValue());
			this.addCheckBoxField(FIELD_EXACT, za.isCaseExact());
			this.addCheckBoxField(FIELD_INVERSE, za.isInverse());

		} else if (condition.getRootExpression() instanceof ZestExpressionStatusCode) {
			ZestExpressionStatusCode za = (ZestExpressionStatusCode) condition.getRootExpression();
			this.addComboField(FIELD_STATUS, HttpStatusCode.CODES, za.getCode());

		} else if (condition.getRootExpression() instanceof ZestExpressionResponseTime) {
			ZestExpressionResponseTime zc = (ZestExpressionResponseTime) condition.getRootExpression();
			this.addCheckBoxField(FIELD_GREATER_THAN, zc.isGreaterThan());
			this.addNumberField(FIELD_RESP_TIME, 0, Integer.MAX_VALUE, (int) zc.getTimeInMs());
			
		} else if (condition.getRootExpression() instanceof ZestExpressionURL) {
			ZestExpressionURL zc = (ZestExpressionURL) condition.getRootExpression();
			this.addMultilineField(FIELD_INC_REGEXS, this.listToStr(zc.getIncludeRegexes()));
			this.addMultilineField(FIELD_EXC_REGEXS, this.listToStr(zc.getExcludeRegexes()));
			
		} else if (condition.getRootExpression() instanceof ZestExpressionLength) {
			ZestExpressionLength zc = (ZestExpressionLength) condition.getRootExpression();
			this.addComboField(FIELD_VARIABLE, this.getVariableNames(), zc.getVariableName());
			this.addNumberField(FIELD_LENGTH, 0, Integer.MAX_VALUE, zc.getLength());
			this.addNumberField(FIELD_APPROX, 0, 100, zc.getApprox());
		}
		this.addPadding();
	}

	private List<String> getVariableNames() {
		ArrayList<String> list = new ArrayList<String>();
		list.addAll(script.getVariableNames());
		Collections.sort(list);
		return list;
	}

	private String listToStr(List<String> list) {
		StringBuilder sb = new StringBuilder();
		for (String str : list) {
			sb.append(str);
			sb.append("\n");
		}
		return sb.toString();
	}

	private List<String> strToList(String str) {
		List<String> list = new ArrayList<String>();
		for (String el : str.split("\n")) {
			if (el.length() > 0) {
				list.add(el);
			}
		}
		return list;
	}

	public void save() {
		if (condition.getRootExpression() instanceof ZestExpressionRegex) {
			ZestExpressionRegex zc = (ZestExpressionRegex) condition
					.getRootExpression();
			zc.setVariableName(this.getStringValue(FIELD_VARIABLE));
			zc.setRegex(this.getStringValue(FIELD_REGEX));
			zc.setCaseExact(this.getBoolValue(FIELD_EXACT));
			zc.setInverse(this.getBoolValue(FIELD_INVERSE));

		} else if (condition.getRootExpression() instanceof ZestExpressionEquals) {
			ZestExpressionEquals zc = (ZestExpressionEquals) condition.getRootExpression();
			zc.setVariableName(this.getStringValue(FIELD_VARIABLE));
			zc.setValue(this.getStringValue(FIELD_VALUE));
			zc.setCaseExact(this.getBoolValue(FIELD_EXACT));
			zc.setInverse(this.getBoolValue(FIELD_INVERSE));

		} else if (condition.getRootExpression() instanceof ZestExpressionStatusCode) {
			ZestExpressionStatusCode zc = (ZestExpressionStatusCode) condition
					.getRootExpression();
			zc.setCode(this.getIntValue(FIELD_STATUS));

		} else if (condition.getRootExpression() instanceof ZestExpressionResponseTime) {
			ZestExpressionResponseTime zc = (ZestExpressionResponseTime) condition
					.getRootExpression();
			zc.setGreaterThan(this.getBoolValue(FIELD_GREATER_THAN));
			zc.setTimeInMs(this.getIntValue(FIELD_RESP_TIME));

		} else if (condition.getRootExpression() instanceof ZestExpressionURL) {
			ZestExpressionURL zc = (ZestExpressionURL) condition
					.getRootExpression();
			zc.setIncludeRegexes(this.strToList(this
					.getStringValue(FIELD_INC_REGEXS)));
			zc.setExcludeRegexes(this.strToList(this
					.getStringValue(FIELD_EXC_REGEXS)));

		} else if (condition.getRootExpression() instanceof ZestExpressionLength) {
			ZestExpressionLength za = (ZestExpressionLength) condition.getRootExpression();
			za.setVariableName(this.getStringValue(FIELD_VARIABLE));
			za.setLength(this.getIntValue(FIELD_LENGTH));
			za.setApprox(this.getIntValue(FIELD_APPROX));

//		}if (this.owner instanceof ZestComplexConditionDialog) {
//			return; //adds to the tree only if the parent is NOT a ZestComplexConditionalDialog
		}// else {
			if (add) {
				if (request == null) {
					ScriptNode condNode = extension.addToParent(parent,
							condition);
					if (surround) {
						extension.setCnpNodes(children);
						extension.setCut(true);
						extension.pasteToNode(condNode);
					}
				} else {
					for (ScriptNode child : children) {
						extension.addAfterRequest(parent, child, request,
								condition);
					}
				}
			} else {
				for (ScriptNode child : children) {
					extension.updated(child);
					extension.display(child, false);
				}
			}
//		}
	}

	@Override
	public String validateFields() {
		if (condition.getRootExpression() instanceof ZestExpressionRegex) {
			if (this.isEmptyField(FIELD_REGEX)) {
				return Constant.messages.getString("zest.dialog.condition.error.regex");
			}
			try {
				Pattern.compile(this.getStringValue(FIELD_REGEX));
			} catch (Exception e) {
				return Constant.messages.getString("zest.dialog.condition.error.regex");
			}
		} else if (condition.getRootExpression() instanceof ZestExpressionEquals) {
			if (this.isEmptyField(FIELD_VALUE)) {
				return Constant.messages.getString("zest.dialog.condition.error.value");
			}
		} else if (condition.getRootExpression() instanceof ZestExpressionURL) {
			try {
				for (String str : this.strToList(this.getStringValue(FIELD_INC_REGEXS))) {
					Pattern.compile(str);
				}
				for (String str : this.strToList(this.getStringValue(FIELD_EXC_REGEXS))) {
					Pattern.compile(str);
				}
			} catch (Exception e) {
				return Constant.messages.getString("zest.dialog.condition.error.regexes");
			}

		}
		return null;
	}

	protected ZestConditional getCondition() {
		return this.condition;
	}
}
