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
package org.zaproxy.zap.extension.zest;

import org.mozilla.zest.core.v1.ZestScript;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.SiteNode;
import org.zaproxy.zap.view.PopupMenuSiteNode;

public class ZestInvokeScriptWithNodeMenu extends PopupMenuSiteNode {

	private static final long serialVersionUID = 2282358266003940700L;
	
	private ExtensionZest extension;
	private ZestScript script;

	public ZestInvokeScriptWithNodeMenu(ExtensionZest extension, ZestScript script) {
		super(script.getTitle(), true);
		this.extension = extension;
		this.script = script;
	}
	
    @Override
    public String getParentMenuName() {
    	return Constant.messages.getString("zest.runscript.popup");
    }
    
    @Override
    public boolean isSubMenu() {
    	return true;
    }

	@Override
	public void performAction(SiteNode sn) throws Exception {
		if (sn != null && sn.getHistoryReference() != null) {
			extension.runScript(script, sn.getHistoryReference().getHttpMessage());
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
