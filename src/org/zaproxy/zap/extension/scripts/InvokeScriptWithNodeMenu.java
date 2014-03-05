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

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.view.PopupMenuSiteNode;

public class InvokeScriptWithNodeMenu extends PopupMenuSiteNode {

	private static final long serialVersionUID = 2282358266003940700L;
    private static Logger logger = Logger.getLogger(InvokeScriptWithNodeMenu.class);

	private ExtensionScriptsUI extension;
	private ScriptWrapper script;
	
	public InvokeScriptWithNodeMenu(ExtensionScriptsUI extension, ScriptWrapper script) {
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
			logger.debug("Invoke script with " + sn.getNodeName());
			try {
				HttpMessage msg = sn.getHistoryReference().getHttpMessage();
				extension.invokeTargetedScript(script, msg);
					
			} catch (Exception e) {
				logger.debug("Script " + script.getName() + " failed with error: " + e.toString());
				extension.showError(e);
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
