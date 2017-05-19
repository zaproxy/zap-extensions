/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrulesAlpha;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

import org.parosproxy.paros.Constant;

import java.io.IOException;

/**
 * Active scan rule which checks whether or not trace.axd is exposed.
 * https://github.com/zaproxy/zaproxy/issues/3280
 * 
 * @author kingthorin+owaspzap@gmail.com
 */
public class TraceAxdScanner extends AbstractAppPlugin {

	private static final String MESSAGE_PREFIX = "ascanalpha.traceaxdscanner.";
	private static final int PLUGIN_ID = 40029;

	private static final Logger LOG = Logger.getLogger(TraceAxdScanner.class);

	@Override
	public int getId() {
		return PLUGIN_ID;
	}

	@Override
	public String getName() {
		return Constant.messages.getString(MESSAGE_PREFIX + "name");
	}

	@Override
	public String getDescription() {
		return Constant.messages.getString(MESSAGE_PREFIX + "desc");
	}

	@Override
	public String getSolution() {
		return Constant.messages.getString(MESSAGE_PREFIX + "soln");
	}

	@Override
	public String getReference() {
		return Constant.messages.getString(MESSAGE_PREFIX + "refs");
	}
	
	private String getOtherInfo() {
		return Constant.messages.getString(MESSAGE_PREFIX + "otherinfo");
	}

	@Override
	public String[] getDependency() {
		return null;
	}

	@Override
	public boolean targets(TechSet technologies) {
		return technologies.includes(Tech.IIS) || technologies.includes(Tech.Windows) || technologies.includes(Tech.ASP)
				|| technologies.includes(Tech.MsSQL);
	}

	@Override
	public int getCategory() {
		return Category.INFO_GATHER;
	}

	@Override
	public int getRisk() {
		return Alert.RISK_MEDIUM;
	}

	@Override
	public int getCweId() {
		return 215; // CWE-215: Information Exposure Through Debug Information
	}

	@Override
	public int getWascId() {
		return 13; // WASC-13: Informatin Leakage
	}

	@Override
	public void init() {

	}

	@Override
	public void scan() {

		// Check if the user stopped things. One request per URL so check before
		// sending the request
		if (isStop()) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("Scanner " + getName() + " Stopping.");
			}
			return;
		}

		HttpMessage newRequest = getNewMsg();
		newRequest.getRequestHeader().setMethod(HttpRequestHeader.GET);
		URI baseUri = getBaseMsg().getRequestHeader().getURI();
		URI elmahUri = null;
		try {
			String baseUriPath = baseUri.getPath() == null ? "" : baseUri.getPath();
			elmahUri = new URI(baseUri.getScheme(), null, baseUri.getHost(), baseUri.getPort(),
					createTestablePath(baseUriPath));
		} catch (URIException uEx) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("An error occurred creating a URI for the: " + getName() + " scanner. " + uEx.getMessage(),
						uEx);
			}
			return;
		}
		try {
			newRequest.getRequestHeader().setURI(elmahUri);
		} catch (URIException uEx) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("An error occurred setting the URI for a new request used by: " + getName() + " scanner. "
						+ uEx.getMessage(), uEx);
			}
			return;
		}
		// Until https://github.com/zaproxy/zaproxy/issues/3563 is addressed track completed in Kb
		// TODO change this when possible
		synchronized (getKb()) {
		    if (getKb().getBoolean(elmahUri, MESSAGE_PREFIX)) {
		        return;
		    }
		    getKb().add(elmahUri, MESSAGE_PREFIX, Boolean.TRUE);
		}
		try {
			sendAndReceive(newRequest, false);
		} catch (IOException e) {
			LOG.warn("An error occurred while checking [" + newRequest.getRequestHeader().getMethod() + "] ["
					+ newRequest.getRequestHeader().getURI() + "] for " + getName() + " Caught "
					+ e.getClass().getName() + " " + e.getMessage());
			return;
		}
		int statusCode = newRequest.getResponseHeader().getStatusCode();
		if (statusCode == HttpStatusCode.OK) {
			raiseAlert(newRequest, getRisk(), "");
		} else if (statusCode == HttpStatusCode.UNAUTHORIZED || statusCode == HttpStatusCode.FORBIDDEN) {
			raiseAlert(newRequest, Alert.RISK_INFO, getOtherInfo());
		}
	}
	
	private String createTestablePath(String baseUriPath) {
		String newPath = "";
		if (baseUriPath.contains("/")) {
			if (baseUriPath.endsWith("/")) {
				newPath = baseUriPath + "trace.axd";
			} else {
				newPath = baseUriPath.substring(0, baseUriPath.lastIndexOf('/')) + "/trace.axd";
			}
		} else {
			newPath = baseUriPath + "/trace.axd";
		}
		return newPath;
	}
	
	private void raiseAlert(HttpMessage msg, int risk, String otherInfo) {
		bingo(risk, // Risk
				Alert.CONFIDENCE_HIGH, // Confidence
				getName(), // Name
				getDescription(), // Description
				msg.getRequestHeader().getURI().toString(), // URI
				null, // Param
				"", // Attack
				otherInfo, // OtherInfo
				getSolution(), // Solution
				msg.getResponseHeader().getPrimeHeader(), // Evidence
				getCweId(), // CWE ID
				getWascId(), // WASC ID
				msg); // HTTPMessage
	}

}
