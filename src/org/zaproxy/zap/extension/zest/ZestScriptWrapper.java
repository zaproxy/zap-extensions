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

import java.io.IOException;

import javax.script.ScriptException;

import org.mozilla.zest.core.v1.ZestJSON;
import org.mozilla.zest.core.v1.ZestScript;
import org.parosproxy.paros.control.Control;
import org.zaproxy.zap.extension.script.ScriptWrapper;

public class ZestScriptWrapper extends ScriptWrapper {

	private boolean incStatusCodeAssertion = true;
	private boolean incLengthAssertion = true;
	private int lengthApprox = 1;
	private ZestScript zestScript = null;
	private ExtensionZest extension = null;

	public ZestScriptWrapper(ScriptWrapper script) {
		zestScript = (ZestScript) ZestJSON.fromString(script.getContents());
		if (zestScript == null) {
			// new script
			zestScript = new ZestScript();
			zestScript.setType(ZestScript.Type.Active);
			zestScript.setDescription(script.getDescription());
		}
		// Override the title in case its taken from a template
		zestScript.setTitle(script.getName());

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
	
	@SuppressWarnings("unchecked")
	public <T> T getInterface(Class<T> class1) throws ScriptException, IOException {
		if (class1.isAssignableFrom(ZestPassiveRunner.class)) {
			return (T) new ZestPassiveRunner(this.getExtension(), this);
			
		} else if (class1.isAssignableFrom(ZestActiveRunner.class)) {
			return (T) new ZestActiveRunner(this.getExtension(), this);
			
		} else if (class1.isAssignableFrom(ZestTargetedRunner.class)) {
			return (T) new ZestTargetedRunner(this.getExtension(), this);
		}
		return null;
	}

	private ExtensionZest getExtension() {
		if (extension == null) {
			extension = (ExtensionZest) Control.getSingleton().getExtensionLoader().getExtension(ExtensionZest.NAME);
		}
		return extension;
	}

}
