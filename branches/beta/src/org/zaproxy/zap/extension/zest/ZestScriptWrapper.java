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
import org.mozilla.zest.core.v1.ZestScript.Type;
import org.parosproxy.paros.control.Control;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.pscan.ExtensionPassiveScan;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;

public class ZestScriptWrapper extends ScriptWrapper {

	private boolean incStatusCodeAssertion = true;
	private boolean incLengthAssertion = true;
	private int lengthApprox = 1;
	private ZestScript zestScript = null;
	private ExtensionZest extension = null;
	private ScriptWrapper original = null;

	public ZestScriptWrapper(ScriptWrapper script) {
		this.original = script;
		zestScript = (ZestScript) ZestJSON.fromString(script.getContents());
		if (zestScript == null) {
			// new script
			zestScript = new ZestScript();
			Type ztype;
			switch (script.getType().getName()) {
			case ExtensionActiveScan.SCRIPT_TYPE_ACTIVE:
				ztype = Type.Active;
				break;
			case ExtensionPassiveScan.SCRIPT_TYPE_PASSIVE:
				ztype = Type.Passive;
				break;
			case ExtensionScript.TYPE_TARGETED:
				ztype = Type.Targeted;
				break;
			case ExtensionScript.TYPE_PROXY:
				// TODO this ok?
				ztype = Type.Targeted;
				break;
			case ExtensionScript.TYPE_STANDALONE:
			default:
				ztype = Type.StandAlone;
				break;
			}
			zestScript.setType(ztype);
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
		this.setChanged(false);
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
			
		} else if (class1.isAssignableFrom(ZestProxyRunner.class)) {
			return (T) new ZestProxyRunner(this.getExtension(), this);
		}
		return null;
	}

	private ExtensionZest getExtension() {
		if (extension == null) {
			extension = (ExtensionZest) Control.getSingleton().getExtensionLoader().getExtension(ExtensionZest.NAME);
		}
		return extension;
	}

	@Override
	public String getContents() {
		return ZestJSON.toString(this.zestScript);
	}

	@Override
	public boolean equals (Object script) {
		return super.equals(script) || this.original.equals(script);
	}
	
	@Override
	public int hashCode() {
		return this.original.hashCode();
	}
	
}
