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

import org.mozilla.zest.core.v1.ZestJSON;
import org.mozilla.zest.core.v1.ZestScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;

public class ZestScriptWrapper extends ScriptWrapper {

	private boolean incStatusCodeAssertion = true;
	private boolean incLengthAssertion = true;
	private int lengthApprox = 1;
	private ZestScript zestScript = null;

	public ZestScriptWrapper(ZestScript.Type type) {
		zestScript = new ZestScript();
		zestScript.setTitle("");
		zestScript.setDescription("");
		zestScript.setType(type);
		
	}

	public ZestScriptWrapper(ScriptWrapper script) {
		zestScript = (ZestScript) ZestJSON.fromString(script.getContents());
		if (zestScript == null) {
			// new script
			zestScript = new ZestScript();
			zestScript.setTitle(script.getName());
			zestScript.setDescription(script.getDescription());
			zestScript.setType(ZestScript.Type.Targeted);
		}
		this.setName(script.getName());
		this.setDescription(script.getDescription());
		this.setEngine(script.getEngine());
		this.setEngineName(script.getEngineName());
		this.setType(script.getType());
		this.setEnabled(script.isEnabled());
		this.setFile(script.getFile());
		this.setContents(script.getContents());
		this.setLoadOnStart(script.isLoadOnStart());
	}

	public boolean isIncStatusCodeAssertion() {
		return incStatusCodeAssertion;
	}

	public void setIncStatusCodeAssertion(boolean incStatusCodeAssertion) {
		this.incStatusCodeAssertion = incStatusCodeAssertion;
	}

	public boolean isIncLengthAssertion() {
		return incLengthAssertion;
	}

	public void setIncLengthAssertion(boolean incLengthAssertion) {
		this.incLengthAssertion = incLengthAssertion;
	}
	
	public int getLengthApprox() {
		return lengthApprox;
	}

	public void setLengthApprox(int lengthApprox) {
		this.lengthApprox = lengthApprox;
	}

	public ZestScript getZestScript() {
		return zestScript;
	}

}
