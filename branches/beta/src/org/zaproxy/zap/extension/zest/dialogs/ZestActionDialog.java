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
import java.util.List;

import org.mozilla.zest.core.v1.ZestAction;
import org.mozilla.zest.core.v1.ZestActionFail;
import org.mozilla.zest.core.v1.ZestActionInvoke;
import org.mozilla.zest.core.v1.ZestActionPrint;
import org.mozilla.zest.core.v1.ZestActionScan;
import org.mozilla.zest.core.v1.ZestActionSleep;
import org.mozilla.zest.core.v1.ZestRequest;
import org.mozilla.zest.core.v1.ZestStatement;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestScriptWrapper;
import org.zaproxy.zap.extension.zest.ZestZapUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

public class ZestActionDialog extends StandardFieldsDialog implements ZestDialog {

	private static final String FIELD_MESSAGE = "zest.dialog.action.label.message"; 
	private static final String FIELD_PARAM = "zest.dialog.action.label.targetparam";
	private static final String FIELD_PRIORITY = "zest.dialog.action.label.priority";
	private static final String FIELD_MILLISECS = "zest.dialog.action.label.millisecs"; 
	private static final String FIELD_SCRIPT = "zest.dialog.action.label.script"; 
	private static final String FIELD_VARIABLE = "zest.dialog.action.label.variable"; 
	private static final String FIELD_PARAMS = "zest.dialog.action.label.params"; 

	private static final String PRIORITY_PREFIX = "zest.dialog.action.priority.";

	private static final long serialVersionUID = 1L;

	private ExtensionZest extension = null;
	private ScriptNode parent = null;
	private ScriptNode child = null;
	private ZestScriptWrapper script = null;
	private ZestStatement request = null;
	private ZestAction action = null;
	private boolean add = false;

	public ZestActionDialog(ExtensionZest ext, Frame owner, Dimension dim) {
		super(owner, "zest.dialog.action.add.title", dim);
		this.extension = ext;
	}

	public void init (ZestScriptWrapper script, ScriptNode parent, ScriptNode child, 
			ZestRequest req, ZestAction action, boolean add) {
		this.script = script;
		this.add = add;
		this.parent = parent;
		this.child = child;
		this.request = req;
		this.action = action;

		this.removeAllFields();
		
		if (add) {
			this.setTitle(Constant.messages.getString("zest.dialog.action.add.title"));
		} else {
			this.setTitle(Constant.messages.getString("zest.dialog.action.edit.title"));
		}

		if (action instanceof ZestActionScan) {
			ZestActionScan za = (ZestActionScan) action;
			List<String> namesList = new ArrayList<String>();
			if (req != null) {
				namesList = this.getParamNames(req.getUrl().getQuery());
				if (req.getData() != null) {
					namesList.addAll(this.getParamNames(req.getData()));
				}
			}
			namesList.add(0, "");	// Allow blank
			this.addComboField(FIELD_PARAM, namesList, za.getTargetParameter());
			
		} else if (action instanceof ZestActionFail) {
			ZestActionFail za = (ZestActionFail) action;
			this.addTextField(FIELD_MESSAGE, za.getMessage());
			String [] priorities = { 
					priorityToStr(ZestActionFail.Priority.INFO),
					priorityToStr(ZestActionFail.Priority.LOW),
					priorityToStr(ZestActionFail.Priority.MEDIUM),
					priorityToStr(ZestActionFail.Priority.HIGH)
			};
			if (za.getPriority() == null) {
				this.addComboField(FIELD_PRIORITY, priorities, priorityToStr(ZestActionFail.Priority.HIGH));
			} else {
				this.addComboField(FIELD_PRIORITY, priorities, 
						priorityToStr(ZestActionFail.Priority.valueOf(za.getPriority())));
			}
			// Enable right click menus
			this.addFieldListener(FIELD_MESSAGE, ZestZapUtils.stdMenuAdapter()); 

		} else if (action instanceof ZestActionPrint) {
			ZestActionPrint za = (ZestActionPrint) action;
			this.addTextField(FIELD_MESSAGE, za.getMessage());
			// Enable right click menus
			this.addFieldListener(FIELD_MESSAGE, ZestZapUtils.stdMenuAdapter()); 
			
		} else if (action instanceof ZestActionSleep) {
			ZestActionSleep za = (ZestActionSleep) action;
			// TODO support longs?
			this.addNumberField(FIELD_MILLISECS, 0, Integer.MAX_VALUE, (int)za.getMilliseconds());
			
		} else if (action instanceof ZestActionInvoke) {
			ZestActionInvoke za = (ZestActionInvoke) action;
			this.addComboField(FIELD_SCRIPT, this.getScriptNames(), za.getScript());
			this.addTextField(FIELD_VARIABLE, za.getVariableName());
			/* TODO params!
			this.addTextField(FIELD_MESSAGE, za.getMessage());
			// Enable right click menus
			this.addFieldListener(FIELD_MESSAGE, ZestZapUtils.stdMenuAdapter());
			*/ 
		}
		this.addPadding();
	}
	
	private String priorityToStr(ZestActionFail.Priority priority) {
		return Constant.messages.getString(PRIORITY_PREFIX + priority.name().toLowerCase());
	}
	
	private ZestActionFail.Priority strToPriority(String str) {
		for (ZestActionFail.Priority p : ZestActionFail.Priority.values()) {
			if (this.priorityToStr(p).equals(str)) {
				return p;
			}
		}
		return null;
	}

	private List<String> getScriptNames() {
		List<String> vals = new ArrayList<String>();
		for (ScriptWrapper script : this.extension.getExtScript().getScripts(ExtensionScript.TYPE_STANDALONE)) {
			if (script.getFile() != null) {
				// Only show scripts we can refer to
				vals.add(script.getName());
			}
		}
		return vals;
	}

	private List<String> getParamNames(String data) {
		List<String> vals = new ArrayList<String>();
		if (data != null && data.length() > 0) {
			String[] nameValues = data.split("&");
			for (String nameValue : nameValues) {
				String[] nvs = nameValue.split("=");
				if (nvs.length == 2) {
					vals.add(nvs[0]);
				}
			}
		}
		return vals;
	}

	public void save() {
		if (action instanceof ZestActionScan) {
			ZestActionScan za = (ZestActionScan) action;
			za.setTargetParameter(this.getStringValue(FIELD_PARAM));
			
		} else if (action instanceof ZestActionFail) {
			ZestActionFail za = (ZestActionFail) action;
			za.setMessage(this.getStringValue(FIELD_MESSAGE));
			za.setPriority(this.strToPriority(this.getStringValue(FIELD_PRIORITY)));

		} else if (action instanceof ZestActionPrint) {
			ZestActionPrint za = (ZestActionPrint) action;
			za.setMessage(this.getStringValue(FIELD_MESSAGE));
			
		} else if (action instanceof ZestActionSleep) {
			ZestActionSleep za = (ZestActionSleep) action;
			za.setMilliseconds(this.getIntValue(FIELD_MILLISECS));
			
		} else if (action instanceof ZestActionInvoke) {
			ZestActionInvoke za = (ZestActionInvoke) action;
			za.setVariableName(this.getStringValue(FIELD_VARIABLE));
			
			ScriptWrapper sc = this.extension.getExtScript().getScript(this.getStringValue(FIELD_SCRIPT));
			
			za.setScript(sc.getFile().getAbsolutePath());
		}

		if (add) {
			if (request == null) {
				extension.addToParent(parent, action);
			} else {
				extension.addAfterRequest(parent, child, request, action);
			}
		} else {
			extension.updated(child);
			extension.display(child, false);
		}
	}

	@Override
	public String validateFields() {
		// Nothing to do
		// TODO check script chosen + variable name exists
		return null;
	}

	@Override
	public ZestScriptWrapper getScript() {
		return this.script;
	}
	
}
