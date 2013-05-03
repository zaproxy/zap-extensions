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
import java.util.List;

import net.htmlparser.jericho.Source;

import org.apache.log4j.Logger;
import org.mozilla.zest.core.v1.ZestActionFail;
import org.mozilla.zest.core.v1.ZestActionFailException;
import org.mozilla.zest.core.v1.ZestResponse;
import org.mozilla.zest.core.v1.ZestStatement;
import org.mozilla.zest.impl.ZestPassiveRunner;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class ZestPassiveScanner extends PluginPassiveScanner {
	
	private ExtensionZest extension = null;
	private PassiveScanThread parent = null;
	private ZestPassiveRunner runner = null;
	private String name = null;
	
	private Logger logger = Logger.getLogger(ZestPassiveScanner.class);

	public ZestPassiveScanner() {
		this.runner = new ZestPassiveRunner();
	}
	
	@Override
	public String getName() {
		if (name == null) {
			// Cache to prevent an NPE when unloaded
			name = Constant.messages.getString("zest.passivescanner.title");
		}
		return name;
	}

	private ExtensionZest getExtension() {
		if (extension == null) {
			extension = (ExtensionZest) Control.getSingleton().getExtensionLoader().getExtension(ExtensionZest.NAME);
		}
		return extension;
	}
	
	private int getId () {
		// TODO choose a more suitable id
		return 12345;
	}
	
	@Override
	public void scanHttpRequestSend(HttpMessage arg0, int arg1) {
		// Do nothing
	}

	@Override
	public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
		if (this.getExtension() != null) {
			List<ZestScriptWrapper> scripts = extension.getPscanScripts();
			try {
				for (ZestScriptWrapper script : scripts) {
					// TODO support enabling/disabling
					ZestResponse resp = ZestZapUtils.toZestResponse(msg);
					for (ZestStatement test : script.getCommonTests()) {
						try {
							resp = runner.runStatement(script, test, resp);
						} catch (ZestActionFailException afe) {
							this.raiseAlert(msg, script, afe);
						} catch (Exception e) {
							logger.error(e.getMessage(), e);
							if (View.isInitialised()) {
								// Also write to Output tab
								View.getSingleton().getOutputPanel().append(e.getMessage() + e.getStackTrace());
							}
						}
					}
				}
			} catch (MalformedURLException e) {
				logger.error(e.getMessage(), e);
			}
		}
	}

	private void raiseAlert(HttpMessage msg, ZestScriptWrapper script, ZestActionFailException afe) {
		Alert alert = new Alert(this.getId(), Alert.RISK_MEDIUM, Alert.SUSPICIOUS, afe.getMessage());
		alert.setMessage(msg);
		alert.setUri(msg.getRequestHeader().getURI().toString());
		alert.setDescription(script.getDescription());
		
		if (afe.getAction() instanceof ZestActionFail) {
			ZestActionFail zaf = (ZestActionFail)afe.getAction();
			if (ZestActionFail.Priority.INFO.name().equals(zaf.getPriority())) {
				alert.setRiskReliability(Alert.RISK_INFO, Alert.WARNING);
			} else if (ZestActionFail.Priority.LOW.name().equals(zaf.getPriority())) {
				alert.setRiskReliability(Alert.RISK_LOW, Alert.WARNING);
			} else if (ZestActionFail.Priority.MEDIUM.name().equals(zaf.getPriority())) {
				alert.setRiskReliability(Alert.RISK_MEDIUM, Alert.WARNING);
			} else if (ZestActionFail.Priority.HIGH.name().equals(zaf.getPriority())) {
				alert.setRiskReliability(Alert.RISK_HIGH, Alert.WARNING);
			}
		}
		parent.raiseAlert(this.getId(), alert);
		
	}

	@Override
	public void setParent(PassiveScanThread parent) {
		this.parent = parent;
	}

}
