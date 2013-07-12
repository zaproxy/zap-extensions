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
package org.zaproxy.zap.extension.scripts;

import java.io.StringWriter;
import java.util.TreeSet;

import javax.script.Invocable;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.view.PopupMenuSiteNode;

public class InvokeScriptWithNodeMenu extends PopupMenuSiteNode {

	private static final long serialVersionUID = 2282358266003940700L;
    //private static Logger logger = Logger.getLogger(InvokeScriptWithNodeMenu.class);

	private ExtensionScripts extension;
	private ScriptWrapper script;
	
	private ScriptsActiveScanner sas = new ScriptsActiveScanner();

	public InvokeScriptWithNodeMenu(ExtensionScripts extension, ScriptWrapper script) {
		super(script.getName(), true);
		this.extension = extension;
		this.script = script;
	}
	
    @Override
    public String getParentMenuName() {
    	return Constant.messages.getString("scripts.runscript.popup");
    }
    
    @Override
    public boolean isSubMenu() {
    	return true;
    }

	@Override
	public void performAction(SiteNode sn) throws Exception {
		if (sn != null && sn.getHistoryReference() != null) {
			// TODO - this will need to use a different interface!
			StringWriter writer = new StringWriter();
			try {
				Invocable inv = extension.invokeScript(script, writer);
					
				ScriptAScan s = inv.getInterface(ScriptAScan.class);
				
				if (s != null) {
					
					HttpMessage msg = sn.getHistoryReference().getHttpMessage();
					TreeSet<HtmlParameter> params = msg.getUrlParams();
					
					for (HtmlParameter param : params) {
						s.scan(sas, msg, param.getName(), param.getValue());
					}
					
				} else {
					writer.append(Constant.messages.getString("scripts.interface.targeted.error"));
					extension.setError(script, writer.toString());
					extension.setEnabled(script, false);
				}
			} catch (Exception e) {
				writer.append(e.toString());
				extension.setError(script, e);
				extension.setEnabled(script, false);
			}
		}		
	}
	
	@Override
	public boolean isEnableForInvoker(Invoker invoker) {
		return true;
	}
	
	@Override
    public boolean isEnabledForSiteNode (SiteNode sn) {
    	return true;
    }

    @Override
    public boolean isSafe() {
    	return true;
    }
}
