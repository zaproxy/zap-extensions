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
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.view.popup.ExtensionPopupMenuComponent;
import org.zaproxy.zap.view.popup.PopupMenuItemHttpMessageContainer;

public class InvokeScriptWithHttpMessageMenu extends PopupMenuItemHttpMessageContainer {

	private static final long serialVersionUID = 2282358266003940700L;
    private static Logger logger = Logger.getLogger(InvokeScriptWithHttpMessageMenu.class);

	private ExtensionScriptsUI extension;
	private ScriptWrapper script;
	
	public InvokeScriptWithHttpMessageMenu(ExtensionScriptsUI extension, ScriptWrapper script) {
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
	public void performAction(HttpMessage msg) {
		logger.debug("Invoke script with " + msg.getRequestHeader().getURI());
		try {
			extension.invokeTargetedScript(script, msg);
				
		} catch (Exception e) {
			logger.debug("Script " + script.getName() + " failed with error: " + e.toString());
			extension.showError(e);
		}
	}
	
    @Override
    public boolean isSafe() {
    	return true;
    }

	@Override
	public void dismissed(ExtensionPopupMenuComponent selectedMenuComponent) {
		View.getSingleton().getPopupList().remove(this);
	}
}
