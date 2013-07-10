/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
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

import java.io.IOException;
import java.io.StringWriter;
import java.util.List;

import javax.script.Invocable;

import org.apache.commons.httpclient.HttpException;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;

public class ScriptsActiveScanner extends AbstractAppParamPlugin {

	private ExtensionScripts extension = null;

    // private static Logger logger = Logger.getLogger(ScriptsActiveScanner.class);
	
    @Override
    public int getId() {
        return 50000;
    }

    @Override
    public String getName() {
    	// TODO this npes due to loading order :(
    	if (Constant.messages.containsKey("scripts.activescanner.title")) {
    		return Constant.messages.getString("scripts.activescanner.title");
    	}
    	return "Script active scan rules";
    }

    @Override
    public String[] getDependency() {
        return null;
    }

    @Override
    public String getDescription() {
        return "N/A";
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        return "N/A";
    }

    @Override
    public String getReference() {
        return "N/A";
    }

    @Override
    public void init() {
    }

	private ExtensionScripts getExtension() {
		if (extension == null) {
			extension = (ExtensionScripts) Control.getSingleton().getExtensionLoader().getExtension(ExtensionScripts.NAME);
		}
		return extension;
	}

    @Override
    public void scan(HttpMessage msg, String param, String value) {
		List<ScriptWrapper> scripts = this.getExtension().getScripts(ScriptWrapper.Type.ACTIVE);
			
		for (ScriptWrapper script : scripts) {
			StringWriter writer = new StringWriter();
			try {
				if (script.isEnabled()) {
					Invocable inv = extension.invokeScript(script, writer);
					
					ScriptAScan s = inv.getInterface(ScriptAScan.class);
					
					if (s != null) {
						s.scan(this, msg, param, value);
						
					} else {
						writer.append(Constant.messages.getString("scripts.interface.passive.error"));
						extension.setError(script, writer.toString());
						extension.setEnabled(script, false);
					}
				}
				
			} catch (Exception e) {
				writer.append(e.toString());
				extension.setError(script, e);
				extension.setEnabled(script, false);
			}
		}
	}
    
    public String setParam(HttpMessage msg, String param, String value) {
    	return super.setParameter(msg, param, value);
    }

    public void sendAndReceive(HttpMessage msg) throws HttpException, IOException {
        super.sendAndReceive(msg);
    }
    
    public void sendAndReceive(HttpMessage msg, boolean isFollowRedirect) throws HttpException, IOException {
    	super.sendAndReceive(msg, isFollowRedirect);
    }

    public void sendAndReceive(HttpMessage msg, boolean isFollowRedirect, boolean handleAntiCSRF) throws HttpException, IOException {
    	super.sendAndReceive(msg, isFollowRedirect, handleAntiCSRF);
    }

	public void raiseAlert(int risk, int reliability, String name, String description, String uri, 
			String param, String attack, String otherInfo, String solution, HttpMessage msg) {
		super.bingo(risk, reliability, name, description, uri, param, attack, otherInfo, solution, msg);
	}

	@Override
	public int getRisk() {
		return Alert.RISK_INFO;
	}

}
