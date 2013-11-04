/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.zest.menu;

import java.awt.Component;
import java.text.MessageFormat;
import java.util.regex.Pattern;

import javax.swing.JTree;

import org.apache.commons.httpclient.URI;
import org.mozilla.zest.core.v1.ZestActionFail;
import org.mozilla.zest.core.v1.ZestComment;
import org.mozilla.zest.core.v1.ZestConditional;
import org.mozilla.zest.core.v1.ZestExpressionRegex;
import org.mozilla.zest.core.v1.ZestJSON;
import org.mozilla.zest.core.v1.ZestScript;
import org.mozilla.zest.core.v1.ZestVariables;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.model.HistoryReference;
import org.zaproxy.zap.extension.alert.AlertNode;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestScriptWrapper;
import org.zaproxy.zap.extension.zest.ZestZapUtils;
import org.zaproxy.zap.view.PopupMenuHistoryReference;

public class ZestGenerateScriptFromAlertMenu extends PopupMenuHistoryReference {

	private static final long serialVersionUID = 2282358266003940700L;
	
	private ExtensionZest extension;

	private JTree alertInvoker = null;
	private Alert lastAlert = null;
	
	/**
	 * This method initializes 
	 * 
	 */
	public ZestGenerateScriptFromAlertMenu(ExtensionZest extension) {
		super(Constant.messages.getString("zest.alert2script.title"), true);
		this.extension = extension;
	}
	    
	public ZestGenerateScriptFromAlertMenu(ExtensionZest extension, ScriptNode parent) {
		super(parent.getNodeName(), true);
		this.extension = extension;
	}
	
	@Override
	public void performAction(HistoryReference href) throws Exception {
		if (href.getHttpMessage() == null) {
			return;
		}
		if (this.lastAlert == null) {
			return;
		} else {
			// Build up a Zest script...
			ZestScript sz = new ZestScript();
			// Build up the default tile
			URI uri = href.getHttpMessage().getRequestHeader().getURI();
			String pathEnd = uri.getPath();
			if (pathEnd.lastIndexOf("/") > 0) {
				pathEnd = pathEnd.substring(pathEnd.lastIndexOf("/")+1);
			}
			String title1 = MessageFormat.format(
					Constant.messages.getString("zest.alert2script.script.name"),
					uri.getHost(), pathEnd, this.lastAlert.getAlert());

			String title2 = title1;
			int i = 2;
			while (this.extension.getExtScript().getScript(title2) != null) {
				// Keep going until we find a unique one, otherwise it will fail
				title2 = title1 + " " + i++;
			}
			
			sz.setTitle(title2);
			// Build up the script description from the alert description, other info and solution 
			StringBuilder sb = new StringBuilder();
			sb.append(this.lastAlert.getDescription());
			if (this.lastAlert.getOtherInfo() != null) {
				sb.append("\n\n");
				sb.append(this.lastAlert.getOtherInfo());
			}
			if (this.lastAlert.getSolution() != null) {
				sb.append("\n\n");
				sb.append(this.lastAlert.getSolution());
			}
			sz.setDescription(sb.toString());
			// Work out a reasonable prefix
			String prefix = this.lastAlert.getUri(); 
			int slash = -1;
			if (prefix != null && prefix.length() > 8) {
				// The 8 is to get past "https://" - which is also good for just http:// 
				slash = prefix.substring(8).indexOf("/");
				if (slash > 0) {
					sz.setPrefix(prefix.substring(0, slash+8));
				}
			}
			
			// Add the request
			sz.add(ZestZapUtils.toZestRequest(this.lastAlert.getMessage()));
			
			String evidence = this.lastAlert.getEvidence();
			if (evidence != null && evidence.length() > 0) {
				ZestConditional zc = null;
				// We have some evidence, can we find it?
				if (this.lastAlert.getMessage().getResponseHeader().toString().contains(evidence)) {
					// Found in the header
					zc = new ZestConditional(new ZestExpressionRegex(ZestVariables.RESPONSE_HEADER, Pattern.quote(evidence)));
				} else if (this.lastAlert.getMessage().getResponseBody().toString().contains(evidence)) {
					// Found in body
					zc = new ZestConditional(new ZestExpressionRegex(ZestVariables.RESPONSE_BODY, Pattern.quote(evidence)));
				}
				if (zc != null) {
					// Found the evidence, add and fail if its found 
					ZestActionFail zaf = new ZestActionFail();
					switch (this.lastAlert.getRisk()) {
					case Alert.RISK_INFO:	zaf.setPriority(ZestActionFail.Priority.INFO); break;
					case Alert.RISK_LOW:	zaf.setPriority(ZestActionFail.Priority.LOW); break;
					case Alert.RISK_MEDIUM:	zaf.setPriority(ZestActionFail.Priority.MEDIUM); break;
					case Alert.RISK_HIGH:	zaf.setPriority(ZestActionFail.Priority.HIGH); break;
					}
					zaf.setMessage(this.lastAlert.getAlert());
					zc.addIf(zaf);
					sz.add(zc);
				} else {
					// Add a suitable comment - evidence not found
					sz.add(new ZestComment(Constant.messages.getString("zest.alert2script.badevidence.comment")));
				}
			} else {
				// Add a suitable comment - no evidence
				sz.add(new ZestComment(Constant.messages.getString("zest.alert2script.noevidence.comment")));
			}
			
			ScriptWrapper sw = new ScriptWrapper();
			sw.setName(sz.getTitle());
			sw.setDescription(sz.getDescription());
			sw.setContents(ZestJSON.toString(sz));
			sw.setType(extension.getExtScript().getScriptType(
					ExtensionScript.TYPE_STANDALONE));
			sw.setEngine(this.extension.getZestEngineWrapper());
			
			ZestScriptWrapper zsw = new ZestScriptWrapper(sw);
			extension.add(zsw , true);
		}
	}
	
	@Override
    public boolean isEnableForComponent(Component invoker) {
		// Need to call this to set up various variables, even though we ignore the result
		super.isEnableForComponent(invoker);
        this.setEnabled(false);
		if (invoker.getName() != null && invoker.getName().equals("treeAlert")) {
        	this.alertInvoker = (JTree) invoker;
            if (alertInvoker.getLastSelectedPathComponent() != null) {
            	if (alertInvoker.getSelectionCount() == 1) {
                	// Note - the Alerts tree only supports single selections
        			AlertNode aNode = (AlertNode) alertInvoker.getLastSelectedPathComponent();
            	    if (aNode.getUserObject() != null) {
            	        if (aNode.getUserObject() instanceof Alert) {
            	            lastAlert = (Alert) aNode.getUserObject();
    	                    this.setEnabled(true);
            	        }
            	    }
            	}
                return true;
            }
		}
		return false;
	}

	
    @Override
    public boolean isSafe() {
    	return true;
    }

	@Override
	public boolean isEnableForInvoker(Invoker invoker) {
		// Not used as isEnableForComponent is overriden 
		return false;
	}
}
