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
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.mozilla.zest.core.v1.ZestAction;
import org.mozilla.zest.core.v1.ZestActionFail;
import org.mozilla.zest.core.v1.ZestActionFailException;
import org.mozilla.zest.core.v1.ZestActionScan;
import org.mozilla.zest.core.v1.ZestAssertFailException;
import org.mozilla.zest.core.v1.ZestAssertion;
import org.mozilla.zest.core.v1.ZestAssignFailException;
import org.mozilla.zest.core.v1.ZestAssignment;
import org.mozilla.zest.core.v1.ZestInvalidCommonTestException;
import org.mozilla.zest.core.v1.ZestRequest;
import org.mozilla.zest.core.v1.ZestResponse;
import org.mozilla.zest.core.v1.ZestScript;
import org.mozilla.zest.core.v1.ZestStatement;
import org.mozilla.zest.impl.ZestBasicRunner;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.HostProcess;
import org.parosproxy.paros.core.scanner.Scanner;
import org.parosproxy.paros.core.scanner.ScannerListener;
import org.parosproxy.paros.core.scanner.ScannerParam;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.ConnectionParam;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.extension.script.ScriptUI;

public class ZestZapRunner extends ZestBasicRunner implements ScannerListener {

    private static final Logger log = Logger.getLogger(ZestZapRunner.class);
	
	private ExtensionZest extension;
	private ZestScriptWrapper wrapper = null;
	private HttpMessage target = null;
	private ZestResultWrapper lastResult = null;
	private HistoryReference lastHref = null;
	private StringWriter writer = new StringWriter();

	private boolean pause = false;
    private boolean isStop = false;
    
    private boolean scanning = false;
    
    private List<Alert> alerts = new ArrayList<Alert>();;

	private ScriptUI scriptUI;
    
    /**
     * 
     */
    public ZestZapRunner(ExtensionZest extension, ZestScriptWrapper wrapper) {
    	super();
    	log.debug("Constructor");
    	this.extension = extension;
    	this.wrapper = wrapper;
    	this.scriptUI = extension.getExtScript().getScriptUI();
    	
	    this.setStopOnAssertFail(false);
	    this.setStopOnTestFail(false);
	    
	    ConnectionParam connParams = Model.getSingleton().getOptionsParam().getConnectionParam();
	    if (connParams.getProxyChainName() != null && connParams.getProxyChainName().length() > 0) {
	    	this.setProxy(connParams.getProxyChainName(), connParams.getProxyChainPort());
	    }
    }
    
	@Override
	public void run(ZestScript script) throws ZestAssertFailException, ZestActionFailException, 
			IOException, ZestInvalidCommonTestException, ZestAssignFailException {
    	log.debug("Run script " + script.getTitle());

		this.target = null;
		super.setOutputWriter(writer);
		super.run(script);
		this.notifyComplete();
	}

	@Override
	public void run (ZestScript script, ZestRequest target) 
			throws ZestAssertFailException, ZestActionFailException, IOException,
			ZestInvalidCommonTestException, ZestAssignFailException {
    	log.debug("Run script " + script.getTitle());
		super.setOutputWriter(writer);
		super.run(script, target);
		this.notifyComplete();
	}
    
    public void stop() {
        isStop = true;
    }
   
	private void notifyComplete() {
		if (wrapper != null) {
			wrapper.setLastOutput(writer.toString());
		}

		if (View.isInitialised()) {
			if (scriptUI != null && scriptUI.isScriptDisplayed(wrapper)) {
				// TODO Should be an easier way to just update output
				scriptUI.displayScript(wrapper);
			}
		}
	
	}

	private void notifyResponse(ZestResultWrapper href) {
		this.lastHref = href;
		if (View.isInitialised()) {
			if (scriptUI != null && scriptUI.isScriptDisplayed(wrapper)) {
				this.extension.addResultToList(href);
			}
		} else {
			// TODO i18n for cmdline??
			try {
				System.out.println("Response: " + href.getURI() + " passed = " + href.isPassed() + " code=" + href.getStatusCode());
			} catch (Exception e) {
				System.err.println(e.getMessage());
			}
		}
	}

	private void notifyActionFailed(ZestActionFailException e) {
		if (e.getAction() instanceof ZestActionFail) {
			int risk = Alert.RISK_LOW;
			ZestActionFail zaf = (ZestActionFail)e.getAction();
			if (ZestActionFail.Priority.INFO.name().equals(zaf.getPriority())) {
				risk = Alert.RISK_INFO;
			} else if (ZestActionFail.Priority.LOW.name().equals(zaf.getPriority())) {
				risk = Alert.RISK_LOW;
			} else if (ZestActionFail.Priority.MEDIUM.name().equals(zaf.getPriority())) {
				risk = Alert.RISK_MEDIUM;
			} else if (ZestActionFail.Priority.HIGH.name().equals(zaf.getPriority())) {
				risk = Alert.RISK_HIGH;
			}
			Alert alert = new Alert(getID(), risk, Alert.WARNING, e.getMessage());
			
			if (lastHref != null) {
				alert.setHistoryRef(lastHref);
				try {
					alert.setUri(lastHref.getURI().toString());
					alert.setMessage(lastHref.getHttpMessage());
				} catch (Exception e1) {
					log.error(e1.getMessage(), e1);
				}
			}
			this.alertFound(alert);
		}
		
		if (View.isInitialised()) {
			if (scriptUI != null && scriptUI.isScriptDisplayed(wrapper)) {
				if (! ZestScript.Type.Passive.name().equals(wrapper.getZestScript().getType())) {
					// Dont try to update passive scripts - they cant make requests so the 
					// last request wont be in the results list
					extension.failLastResult(e);
				}
			}
		} else {
			// TODO i18n for cmdline??
			// TODO check type first? toUiFailureString as above?
			System.out.println("Action: failed: " + e.getMessage());
		}
	}
	
	private int getID() {
		// TODO Auto-generated method stub
		return 0;
	}

	private void notifyAssignFailed(ZestAssignFailException e) {
		if (View.isInitialised()) {
			if (scriptUI != null && scriptUI.isScriptDisplayed(wrapper)) {
				if (! ZestScript.Type.Passive.equals(wrapper.getZestScript().getType())) {
					// Dont try to update passive scripts - they cant make requests so the 
					// last request wont be in the results list
					extension.failLastResult(e);
				}
			}			
		} else {
			// TODO i18n for cmdline??
			// TODO check type first? toUiFailureString as above?
			System.out.println("Assign: failed: " + e.getMessage());
		}
	}

	@Override
	public ZestResponse runStatement(ZestScript script, ZestStatement stmt, ZestResponse lastResponse)
			throws ZestAssertFailException, ZestActionFailException, 
			ZestInvalidCommonTestException, IOException, ZestAssignFailException {
		while (this.isPaused() && ! this.isStop) {
			try {
				Thread.sleep(200);
			} catch (InterruptedException e) {
				// Ignore
			}
		}
		if (this.isStop) {
			return null;
		}
		return super.runStatement(script, stmt, lastResponse);
	}

	@Override
	public String handleAction(ZestScript script, ZestAction action, ZestResponse lastResponse) throws ZestActionFailException {
		if (action instanceof ZestActionScan) {
			this.invokeScan(script, (ZestActionScan)action);
		} else {
			try {
				return super.handleAction(script, action, lastResponse);
			} catch (ZestActionFailException e) {
				notifyActionFailed(e); 
			}
		}
		return null;
	}

	@Override
	public String handleAssignment(ZestScript script, ZestAssignment assign, ZestResponse lastResponse) throws ZestAssignFailException {
		try {
			return super.handleAssignment(script, assign, lastResponse);
		} catch (ZestAssignFailException e) {
			notifyAssignFailed(e); 
		}
		return null;
	}

	public void handleResponse(ZestRequest request, ZestResponse response) throws ZestAssertFailException {
	    try {
			HttpMessage msg = ZestZapUtils.toHttpMessage(request, response);
			
			ZestResultWrapper zrw = new ZestResultWrapper(Model.getSingleton().getSession(), 
					11 /* Change to HistoryReference.TYPE_ZEST */, msg, request.getIndex());
			
			lastResult = zrw;

			if (request.getAssertions().size() == 0) {
				zrw.setPassed(true);
			} else {
				for (ZestAssertion za : request.getAssertions()) {
					if (za.isValid(response)) {
						zrw.setPassed(true);
					} else {
						zrw.setPassed(false);
						zrw.setMessage(ZestZapUtils.toUiFailureString(za, response));
						break;
					}
				}
			}
			this.notifyResponse(zrw);

	    } catch (Exception e) {
	    	log.error(e.getMessage(), e);
		}
	}
	
	private void invokeScan(ZestScript script, ZestActionScan scan) throws ZestActionFailException {
		this.alerts = new ArrayList<Alert>();
		
		ScannerParam scannerParam = new ScannerParam();
		Scanner scanner = new Scanner(scannerParam, Model.getSingleton().getOptionsParam().getConnectionParam());
		scanner.setScanChildren(false);
		scanner.addScannerListener(this);
		
		if (this.lastResult != null) {
			SiteNode fakeRoot = new SiteNode(null, 11, "");
			SiteNode sn = new SiteNode(null, 11, "");
			sn.setHistoryReference(this.lastResult);
			fakeRoot.add(sn);
			scanning = true;
			scanner.setStartNode(sn);
			scanner.start(sn);
			
			while (scanning) {
				try {
					Thread.sleep(100);
				} catch (InterruptedException e) {
					// Ignore
				}
			}
		}
		if (alerts.size() > 0) {
			// Add all to alerts tab, flags in Script results.. 
			this.lastResult.setPassed(false);
			this.lastResult.setMessage(alerts.get(0).getAlert());
			extension.notifyChanged(this.lastResult);
		}
		
	}

	public boolean isStop() {
	    return isStop;
	}
	
	public void pause() {
		this.pause = true;
	}
	
	public void resume () {
		this.pause = false;
	}
	
	public boolean isPaused() {
		return pause;
	}

	@Override
	public void scannerComplete() {
		this.scanning = false;
	}

	@Override
	public void hostNewScan(String hostAndPort, HostProcess hostThread) {
	}


	@Override
	public void hostProgress(String hostAndPort, String msg, int percentage) {
	}


	@Override
	public void hostComplete(String hostAndPort) {
	}


	@Override
	public void alertFound(Alert alert) {
		this.alerts.add(alert);
		
		ExtensionAlert extAlert = (ExtensionAlert) Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.NAME);
		if (extAlert != null) {
			extAlert.alertFound(alert, alert.getHistoryRef());
		}
		
		extension.notifyAlert(alert);
	}

	public HttpMessage getTarget() {
		return target;
	}

	public void setTarget(HttpMessage target) {
		this.target = target;
	}

	@Override
	public void notifyNewMessage(HttpMessage msg) {
		try {
			ZestResultWrapper zrw = new ZestResultWrapper(Model.getSingleton().getSession(), 
					11 /* Change to HistoryReference.TYPE_ZEST */, msg, -1);
			zrw.setType(ZestResultWrapper.Type.scanAction);
			
			this.notifyResponse(zrw);
			
		} catch (Exception e) {
			log.error(e.getMessage(), e);
		}
	}

	public void setWrapper(ZestScriptWrapper wrapper) {
		this.wrapper = wrapper;
	}

}
