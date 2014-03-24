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

import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import net.htmlparser.jericho.Source;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.encoder.Base64;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;



/**
 * A class to passively scan responses for Base64 encoded data, including ASP ViewState data, which is Base64 encoded.  
 * @author 70pointer@gmail.com
 *
 */
public class Base64Disclosure extends PluginPassiveScanner {

	private PassiveScanThread parent = null;

	/**
	 * a pattern used to identify Base64 encoded data. Set a minimum length to reduce false positives.
	 * Note that because we only look for patterns ending in at least one "=", we will have false negatives (ie, we will not detect ALL Base64 references).
	 * If we do not include this condition, however, we will have a very large number of false positives.
	 * TODO: find a different way to reduce false positives without causing false negatives.
	 */
	static Pattern base64Pattern = Pattern.compile("[a-zA-Z0-9\\+\\\\/]{30,}={1,2}");

	private static Logger log = Logger.getLogger(Base64Disclosure.class);
	
	/**
	 * Prefix for internationalized messages used by this rule
	 */
	private static final String MESSAGE_PREFIX = "pscanalpha.base64disclosure.";

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
		//TODO: implement checks for base64 encoding in the request?
	}

	/**
	 * scans the HTTP response for base64 signatures
	 * @param msg
	 * @param id
	 * @param source unused
	 */
	@Override
	public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {

		if (log.isDebugEnabled()) log.debug("Checking message "+ msg + " for Base64 encoded data");

		//get the body contents as a String, so we can match against it
		String responseheader = msg.getResponseHeader().getHeadersAsString();
		String responsebody = new String (msg.getResponseBody().getBytes());
		String [] responseparts = {responseheader, responsebody};

		if (log.isDebugEnabled()) log.debug("Trying Base64 Pattern: "+ base64Pattern );
		for (String haystack: responseparts) {
			Matcher matcher = base64Pattern.matcher(haystack);
			while (matcher.find()) {
				String evidence = matcher.group();
				byte[] decodeddata=null;
				try {
					//decode the data
					decodeddata = Base64.decode(evidence);             	
				} catch (IOException e) {
					//it's not actually Base64. so skip it.
					if (log.isDebugEnabled()) log.debug("["+evidence + "] could not be decoded as Base64 data");
					continue;
				}
				if (log.isDebugEnabled()) log.debug("Found a match for Base64:" + evidence);

				//so it's valid Base64.  Is it valid .NET ViewState data?
				//This will be true for both __VIEWSTATE and __EVENTVALIDATION data, although currently, we can only interpret/decode __VIEWSTATE.
				boolean validviewstate = false;
				boolean macless = false;
				String viewstatexml = null;
				if ( decodeddata[0]==-1 || decodeddata[1]==0x01 ) {
					//TODO: decode __EVENTVALIDATION data
					ViewStateDecoder viewstatedecoded = new ViewStateDecoder ();					
					try {
						if (log.isDebugEnabled()) log.debug("The following Base64 string has a ViewState preamble: ["+evidence + "]");
						viewstatexml = viewstatedecoded.decode(evidence.getBytes());
						if (log.isDebugEnabled()) log.debug("The data was successfully decoded as ViewState data");
						validviewstate = true;

						//is the ViewState protected by a MAC?
						Matcher hmaclessmatcher = ViewStateDecoder.patternNoHMAC.matcher(viewstatexml);
						macless = hmaclessmatcher.find();
						
						if (log.isDebugEnabled()) log.debug("MACles??? "+ macless);
					} catch (Exception e) {
						//no need to do anything here.. just don't set "validviewstate" to true :)
						e.printStackTrace();
						if (log.isDebugEnabled()) log.debug("The Base64 value ["+ evidence+"] has a valid ViewState pre-amble, but is not a valid viewstate. It may be an EVENTVALIDATION value, is not yet decodable.");
					} 
				} 

				if (validviewstate == true) {
					if (log.isDebugEnabled()) log.debug("Raising a ViewState informational alert");
					
					//raise an (informational) Alert with the human readable ViewState data
					Alert alert = new Alert(getId(), Alert.RISK_INFO, Alert.WARNING, Constant.messages.getString("pscanalpha.base64disclosure.viewstate.name"));
					alert.setDetail(
							Constant.messages.getString("pscanalpha.base64disclosure.viewstate.desc"), 
							msg.getRequestHeader().getURI().toString(), 
							"", //param
							viewstatexml, //TODO: this should be the the attack (NULL).  Set this field to NULL, once Zap allows mutiple alerts on the same URL, with just different evidence 
							Constant.messages.getString("pscanalpha.base64disclosure.viewstate.extrainfo", viewstatexml), //other info
							Constant.messages.getString("pscanalpha.base64disclosure.viewstate.soln"), 
							Constant.messages.getString("pscanalpha.base64disclosure.viewstate.refs"), 
							viewstatexml,
							200, //Information Exposure, 
							13, //Information Leakage
							msg);  
					parent.raiseAlert(id, alert);
					//do NOT break at this point.. we need to find *all* the issues
					
					//if the ViewState is not protected by a MAC, alert it as a High, cos we can mess with the parameters for sure..
					if ( macless ) {
						Alert alertmacless = new Alert(getId(), Alert.RISK_HIGH, Alert.WARNING, Constant.messages.getString("pscanalpha.base64disclosure.viewstatewithoutmac.name"));
						alertmacless.setDetail(
								Constant.messages.getString("pscanalpha.base64disclosure.viewstatewithoutmac.desc"), 
								msg.getRequestHeader().getURI().toString(), 
								"", //param
								viewstatexml, //TODO: this should be the the attack (NULL).  Set this field to NULL, once Zap allows mutiple alerts on the same URL, with just different evidence 
								Constant.messages.getString("pscanalpha.base64disclosure.viewstatewithoutmac.extrainfo", viewstatexml), //other info
								Constant.messages.getString("pscanalpha.base64disclosure.viewstatewithoutmac.soln"), 
								Constant.messages.getString("pscanalpha.base64disclosure.viewstatewithoutmac.refs"), 
								viewstatexml,
								642, //CWE-642 = External Control of Critical State Data 
								13, //Information Leakage
								msg);  
						parent.raiseAlert(id, alertmacless);
						//do NOT break at this point.. we need to find *all* the issues
					}
					
					
					//TODO: if the ViewState contains sensitive data, alert it (particularly if running over HTTP)					
					} 
				else {
					if (log.isDebugEnabled()) log.debug("Raising a Base64 informational alert");
					
					//the Base64 decoded data is not a valid ViewState (even though it may have a valid ViewStatet pre-amble) 
					//so treat it as normal Base64 data, and raise an informational alert.
					if ( evidence!=null && evidence.length() > 0) {
						Alert alert = new Alert(getId(), Alert.RISK_INFO, Alert.WARNING, getName() );
						alert.setDetail(
								getDescription(), 
								msg.getRequestHeader().getURI().toString(), 
								"", //param
								evidence, //TODO: this should be the the attack (NULL).  Set this field to NULL, once Zap allows mutiple alerts on the same URL, with just different evidence 
								getExtraInfo(msg, evidence, decodeddata),  //other info
								getSolution(), 
								getReference(), 
								evidence,
								200, //Information Exposure, 
								13, //Information Leakage
								msg);  
						parent.raiseAlert(id, alert);
						//do NOT break at this point.. we need to find *all* the potential Base64 encoded data in the response..
					}
				}
			}
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
	private int getId() {
		return 10094;
	}

	/**
	 * get the description of the alert
	 * @return
	 */
	private String getDescription() {
		return Constant.messages.getString(MESSAGE_PREFIX + "desc");
	}

	/**
	 * get the solution for the alert
	 * @return
	 */
	private String getSolution() {
		return Constant.messages.getString(MESSAGE_PREFIX + "soln");
	}

	/**
	 * gets references for the alert
	 * @return
	 */
	private String getReference() {
		return Constant.messages.getString(MESSAGE_PREFIX + "refs");
	}

	/**
	 * gets extra information associated with the alert
	 * @param msg
	 * @param arg0
	 * @return
	 */
	private String getExtraInfo(HttpMessage msg, String evidence, byte [] decodeddata) {				
		return Constant.messages.getString(MESSAGE_PREFIX + "extrainfo", evidence, new String (decodeddata));        
	}


}
