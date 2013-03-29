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

import java.sql.SQLException;
import java.util.Date;

import javax.swing.DefaultListModel;

import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.HostProcess;
import org.parosproxy.paros.core.scanner.ScannerListener;
import org.parosproxy.paros.core.scanner.ScannerParam;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.ConnectionParam;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

public class ActiveScan extends org.parosproxy.paros.core.scanner.Scanner implements ScannerListener {

	private boolean isAlive = false;
	private DefaultListModel<HistoryReference> list = new DefaultListModel<>();
	private SiteNode startNode = null;
	private int totalRequests = 0;
	private Date timeStarted = null;
	private Date timeFinished = null;
	
	
	private static final Logger log = Logger.getLogger(ActiveScan.class);

	public ActiveScan(SiteNode startNode, ScannerParam scannerParam, ConnectionParam param/*, ActiveScanPanel activeScanPanel*/) {
		super(scannerParam, param);
		this.startNode = startNode;
		this.addScannerListener(this);
	
	}

	public boolean isRunning() {
		return isAlive;
	}


	public void start() {
		isAlive = true;
		this.timeStarted = new Date();
		this.start(startNode);
	}

/**/
	@Override
	public void alertFound(Alert alert) {
	}

	@Override
	public void hostComplete(String hostAndPort) {
		isAlive = false;
	}

	@Override
	public void hostNewScan(String hostAndPort, HostProcess hostThread) {
	}

	@Override
	public void hostProgress(String hostAndPort, String msg, int percentage) {
	}

	@Override
	public void scannerComplete() {
		this.timeFinished = new Date();
	}

	public DefaultListModel<HistoryReference> getList() {
		return list;
	}
	
	@Override
	public void notifyNewMessage(final HttpMessage msg) {
	    synchronized (list) {
	        HistoryReference hRef = msg.getHistoryRef();
        	this.totalRequests++;
            if (hRef == null) {
                try {
                    hRef = new HistoryReference(Model.getSingleton().getSession(), HistoryReference.TYPE_TEMPORARY, msg);
                    // If an alert is raised because of the HttpMessage msg a new HistoryReference must be created 
                    // (because hRef is temporary), and the condition to create it is when the HistoryReference of the 
                    // Alert "retrieved" through the HttpMessage is null. So it must be set to null.
                    msg.setHistoryRef(null);
                    this.list.addElement(hRef);
                } catch (HttpMalformedHeaderException e) {
                    log.error(e.getMessage(), e);
                } catch (SQLException e) {
                    log.error(e.getMessage(), e);
                }
            } else {
                this.list.addElement(hRef);
            }
        }
	}

	@Override
	public void setStartNode(SiteNode startNode) {
		this.startNode = startNode;
		super.setStartNode(startNode);
	}

	public void reset() {
        this.list = new DefaultListModel<>();
	}

	public int getTotalRequests() {
		return totalRequests;
	}

	public Date getTimeStarted() {
		return timeStarted;
	}

	public Date getTimeFinished() {
		return timeFinished;
	}

}
