/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP development team
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
package org.zaproxy.zap.extension.pscanrulesAlpha;

import net.htmlparser.jericho.Source;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * A class to passively scan responses for Cross Domain MisConfigurations, 
 * which relax the Same Origin Policy in the web browser, for instance.
 * The current implementation looks at excessively permissive CORS headers.  
 * 
 * @author 70pointer@gmail.com
 *
 */
public class CrossDomainMisconfiguration extends PluginPassiveScanner {

	private PassiveScanThread parent = null;

	/**
	 * the logger. it logs stuff.
	 */
	private static Logger log = Logger.getLogger(CrossDomainMisconfiguration.class);

	/**
	 * Prefix for internationalized messages used by this rule
	 */
	private static final String MESSAGE_PREFIX = "pscanalpha.crossdomain.";

	/**
	 * gets the name of the scanner
	 * @return
	 */
	@Override
	public String getName() {
		return Constant.messages.getString(MESSAGE_PREFIX + "name");
	}


	/**
	 * scans the HTTP request sent (in fact, does nothing)
	 * @param msg
	 * @param id
	 */
	@Override
	public void scanHttpRequestSend(HttpMessage msg, int id) {		
	}

	/**
	 * scans the HTTP response for cross-domain mis-configurations
	 * @param msg
	 * @param id
	 * @param source unused
	 */
	@Override
	public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {

		try {
		if (log.isDebugEnabled()) log.debug("Checking message "+ msg.getRequestHeader().getURI().getURI() + " for Cross-Domain misconfigurations");

		//TODO: replace with equivalent names in HttpHeaders, once these headers are available there 
		String ACCESS_CONTROL_ALLOW_ORIGIN = "Access-Control-Allow-Origin";
		//String ACCESS_CONTROL_ALLOW_HEADERS = "Access-Control-Allow-Headers";
		//String ACCESS_CONTROL_ALLOW_METHODS = "Access-Control-Allow-Methods";
		//String ACCESS_CONTROL_EXPOSE_HEADERS = "Access-Control-Expose-Headers";
		
		String corsAllowOriginValue = msg.getResponseHeader().getHeader(ACCESS_CONTROL_ALLOW_ORIGIN);
		//String corsAllowHeadersValue = msg.getResponseHeader().getHeader(ACCESS_CONTROL_ALLOW_HEADERS);
		//String corsAllowMethodsValue = msg.getResponseHeader().getHeader(ACCESS_CONTROL_ALLOW_METHODS);
		//String corsExposeHeadersValue = msg.getResponseHeader().getHeader(ACCESS_CONTROL_EXPOSE_HEADERS);
		
		if ( corsAllowOriginValue!= null && corsAllowOriginValue.equals("*")) {
			if (log.isDebugEnabled()) log.debug("Raising a Cross Domain alert on "+ ACCESS_CONTROL_ALLOW_ORIGIN);
			Alert alert = new Alert(getPluginId(), Alert.RISK_HIGH, Alert.WARNING, getName() );
			alert.setDetail(
					getDescription(), 
					msg.getRequestHeader().getURI().toString(), 
					"", //param
					"", //attack 
					Constant.messages.getString(MESSAGE_PREFIX + "extrainfo"),  //other info
					Constant.messages.getString(MESSAGE_PREFIX + "soln"), 
					Constant.messages.getString(MESSAGE_PREFIX + "refs"), 
					ACCESS_CONTROL_ALLOW_ORIGIN + ": "+ corsAllowOriginValue,
					264, //CWE 264: Permissions, Privileges, and Access Controls 
					14,  //WASC-14: Server Misconfiguration
					msg);  
			parent.raiseAlert(id, alert);
		}
		}
		catch (Exception e) {
			log.error("An error occurred trying to passively scan a message for Cross Domain Misconfigurations");
		}
		
	}
		
	

	/**
	 * sets the parent
	 * @param parent
	 */
	@Override
	public void setParent(PassiveScanThread parent) {
		this.parent = parent;
	}

	/**
	 * get the id of the scanner
	 * @return
	 */
	@Override
	public int getPluginId() {
		return 10098;
	}

	/**
	 * get the description of the alert
	 * @return
	 */
	private String getDescription() {
		return Constant.messages.getString(MESSAGE_PREFIX + "desc");
	}	

}

