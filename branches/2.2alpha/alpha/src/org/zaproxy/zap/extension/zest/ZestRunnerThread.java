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
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.mozilla.zest.core.v1.ZestAction;
import org.mozilla.zest.core.v1.ZestActionFailException;
import org.mozilla.zest.core.v1.ZestActionScan;
import org.mozilla.zest.core.v1.ZestAssertFailException;
import org.mozilla.zest.core.v1.ZestAssertion;
import org.mozilla.zest.core.v1.ZestInvalidCommonTestException;
import org.mozilla.zest.core.v1.ZestRequest;
import org.mozilla.zest.core.v1.ZestResponse;
import org.mozilla.zest.core.v1.ZestScript;
import org.mozilla.zest.core.v1.ZestStatement;
import org.mozilla.zest.core.v1.ZestTransformFailException;
import org.mozilla.zest.core.v1.ZestTransformation;
import org.mozilla.zest.impl.ZestBasicRunner;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.HostProcess;
import org.parosproxy.paros.core.scanner.Scanner;
import org.parosproxy.paros.core.scanner.ScannerListener;
import org.parosproxy.paros.core.scanner.ScannerParam;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.ConnectionParam;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.alert.ExtensionAlert;

public class ZestRunnerThread extends ZestBasicRunner implements Runnable, ScannerListener {

    private static final Logger log = Logger.getLogger(ZestRunnerThread.class);
	
	private List<ZestRunnerListener> listenerList = new ArrayList<>();

	private ExtensionZest extension;
	private ZestScript script = null;
	private HttpMessage target = null;
    //private HttpSender httpSender;
	private ZestResultWrapper lastResult = null;

	private boolean pause = false;
    private boolean isStop = false;
    
    private boolean scanning = false;
    
    private List<Alert> alerts = null;
    
    /**
     * 
     */
    public ZestRunnerThread(ExtensionZest extension, ZestScript script) {
    	super();
    	this.extension = extension;
	    this.script = script;
	    this.setStopOnAssertFail(false);
	    this.setStopOnTestFail(false);
	    
	    ConnectionParam connParams = Model.getSingleton().getOptionsParam().getConnectionParam();
	    if (connParams.getProxyChainName() != null && connParams.getProxyChainName().length() > 0) {
	    	this.setProxy(connParams.getProxyChainName(), connParams.getProxyChainPort());
	    }
    }
    
    
    public void start() {
        isStop = false;
        lastResult = null;
        
        Thread thread = new Thread(this, "ZAP-ZestRunner");
        thread.setPriority(Thread.NORM_PRIORITY-2);
        thread.start();
    }
    
    public void stop() {
        isStop = true;
    }
   
	public void addListener(ZestRunnerListener listener) {
		listenerList.add(listener);		
	}

	public void removeListener(ZestRunnerListener listener) {
		listenerList.remove(listener);
	}

	private void notifyComplete() {
		for (ZestRunnerListener listener : listenerList) {
			listener.notifyComplete();
		}
	}

	private void notifyResponse(ZestResultWrapper href) {
		for (ZestRunnerListener listener : listenerList) {
			listener.notifyResponse(href);
		}
	}

	private void notifyActionFailed(ZestActionFailException e) {
		for (ZestRunnerListener listener : listenerList) {
			listener.notifyActionFail(e);
		}
	}
	
	private void notifyZestInvalidCommonTestFailed (ZestInvalidCommonTestException e) {
		for (ZestRunnerListener listener : listenerList) {
			listener.notifyZestInvalidCommonTestFail(e);
		}
	}

    @Override
    public void run() {
        log.info("Zest Runner started");
		try {
			if (target != null) {
				ZestRequest targetRequest = ZestZapUtils.toZestRequest(target);
				this.run(script, targetRequest);
			} else {
				this.run(script);
			}
		} catch (Exception e) {
			log.error(e.getMessage(), e);
		}
	    
	    notifyComplete();
	    
        log.info("Zest Runner stopped");
	}
    
	@Override
	public ZestResponse runStatement(ZestScript script, ZestStatement stmt, ZestResponse lastResponse)
			throws ZestAssertFailException, ZestActionFailException, ZestTransformFailException, 
			ZestInvalidCommonTestException, IOException {
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
	public void runCommonTest(ZestStatement stmt, ZestResponse response) throws ZestActionFailException, ZestInvalidCommonTestException {
		try {
			super.runCommonTest(stmt, response);
		} catch (ZestActionFailException e) {
			notifyActionFailed(e);
			
		} catch (ZestInvalidCommonTestException e) {
			notifyZestInvalidCommonTestFailed(e);
		}
	}

    
	@Override
	public String handleAction(ZestScript script, ZestAction action, ZestResponse lastResponse) throws ZestActionFailException {
		if (action instanceof ZestActionScan) {
			this.invokeScan(script, (ZestActionScan)action);
		} else {
			// TODO dont really need to pass last action in from Zest?
			try {
				return super.handleAction(script, action, lastResponse);
			} catch (ZestActionFailException e) {
				notifyActionFailed(e); 
			}
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
	
	public void handleTransform (ZestRequest request, ZestTransformation transform) {
		try {
			super.handleTransform(request, transform);
		} catch (ZestTransformFailException e) {
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

}
