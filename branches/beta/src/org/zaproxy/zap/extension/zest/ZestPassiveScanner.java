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

import java.net.MalformedURLException;

import net.htmlparser.jericho.Source;

import org.apache.log4j.Logger;
import org.mozilla.zest.core.v1.ZestActionFail;
import org.mozilla.zest.core.v1.ZestActionFailException;
import org.mozilla.zest.core.v1.ZestResponse;
import org.mozilla.zest.core.v1.ZestStatement;
import org.mozilla.zest.impl.ZestPassiveRunner;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.pscan.PassiveScript;
import org.zaproxy.zap.extension.pscan.scanner.ScriptsPassiveScanner;

public class ZestPassiveScanner implements PassiveScript {
	
	private ExtensionZest extension = null;
	private ZestPassiveRunner runner = null;
	private ZestScriptWrapper script = null;
	
	private Logger logger = Logger.getLogger(ZestPassiveScanner.class);

	public ZestPassiveScanner(ZestScriptWrapper script) {
		this.runner = new ZestPassiveRunner();
		this.script = script;
	}

	private ExtensionZest getExtension() {
		if (extension == null) {
			extension = (ExtensionZest) Control.getSingleton().getExtensionLoader().getExtension(ExtensionZest.NAME);
		}
		return extension;
	}
	
	private void raiseAlert(ScriptsPassiveScanner scriptsPassiveScanner, HttpMessage msg, 
			ZestScriptWrapper script, ZestActionFailException afe) {
		
		int risk = Alert.RISK_LOW;
		
		if (afe.getAction() instanceof ZestActionFail) {
			ZestActionFail zaf = (ZestActionFail)afe.getAction();
			if (ZestActionFail.Priority.INFO.name().equals(zaf.getPriority())) {
				risk = Alert.RISK_INFO;
			} else if (ZestActionFail.Priority.LOW.name().equals(zaf.getPriority())) {
				risk = Alert.RISK_LOW;
			} else if (ZestActionFail.Priority.MEDIUM.name().equals(zaf.getPriority())) {
				risk = Alert.RISK_MEDIUM;
			} else if (ZestActionFail.Priority.HIGH.name().equals(zaf.getPriority())) {
				risk = Alert.RISK_HIGH;
			}
		}
		
		scriptsPassiveScanner.raiseAlert(risk, Alert.WARNING, afe.getMessage(), script.getDescription(), 
				msg.getRequestHeader().getURI().toString(), "", "", "", "", "", -1, -1, msg);
		
	}

	@Override
	public void scan(ScriptsPassiveScanner scriptsPassiveScanner, HttpMessage msg, Source source) {
		logger.debug("Zest PAssiveScan script: " + this.script.getName());
		if (this.getExtension() != null) {
			try {
				ZestResponse resp = ZestZapUtils.toZestResponse(msg);
				for (ZestStatement test : script.getZestScript().getStatements()) {
					try {
						resp = runner.runStatement(script.getZestScript(), test, resp);
					} catch (ZestActionFailException afe) {
						this.raiseAlert(scriptsPassiveScanner, msg, script, afe);
					} catch (Exception e) {
						logger.error(e.getMessage(), e);
						if (View.isInitialised()) {
							// Also write to Output tab
							View.getSingleton().getOutputPanel().append(e.getMessage() + e.getStackTrace());
						}
					}
				}
			} catch (MalformedURLException e) {
				logger.error(e.getMessage(), e);
			}
		}
	}

}
