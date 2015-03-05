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

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import net.htmlparser.jericho.Source;

import org.apache.commons.httpclient.URIException;
import org.apache.http.HttpHeaders;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;



/**
 * A class to passively scan responses for Timestamps, since these *may* be interesting from a security standpoint 
 * @author 70pointer@gmail.com
 *
 */

public class TimestampDisclosureScanner extends PluginPassiveScanner {
	
	private PassiveScanThread parent = null;
	
	/**
	 * a map of a regular expression pattern to details of the timestamp type found 
	 */
	static Map <Pattern, String> timestampPatterns = new HashMap <Pattern, String> ();
	
	static {
		//8 - 10 digits is unlikely to cause many false positives, but covers most of the range of possible Unix time values 
		//as well as all of the current Unix time value (beyond the range for a valid Unix time, in fact)
		timestampPatterns.put(Pattern.compile("\\b[0-9]{8,10}\\b", Pattern.CASE_INSENSITIVE), "Unix");
	}
	
	private static Logger log = Logger.getLogger(TimestampDisclosureScanner.class);

	/**
	 * Prefix for internationalized messages used by this rule
	 */
	private static final String MESSAGE_PREFIX = "pscanalpha.timestampdisclosure.";
	
	/**
	 * ignore the following response headers for the purposes of the comparison, since they cause false positives
	 */
	private static final String [] RESPONSE_HEADERS_TO_IGNORE = {HttpHeader._KEEP_ALIVE, HttpHeaders.CACHE_CONTROL, HttpHeaders.ETAG, HttpHeaders.AGE};  

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
		//TODO: implement checks for timestamps in the request?
	}

	/**
	 * scans the HTTP response for timestamp signatures
	 * @param msg
	 * @param id
	 * @param source unused
	 */
	@Override
	public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
		try {
			if (log.isDebugEnabled())			
				log.debug("Checking message "+ msg.getRequestHeader().getURI().getURI() + " for timestamps");

			List <HttpHeaderField> responseheaders = msg.getResponseHeader().getHeaders();
			StringBuffer filteredResponseheaders = new StringBuffer ();
			for (HttpHeaderField responseheader: responseheaders) {
				boolean ignoreHeader = false;
				for (String headerToIgnore: RESPONSE_HEADERS_TO_IGNORE) {					
					if (responseheader.getName().equalsIgnoreCase(headerToIgnore)) {
						if (log.isDebugEnabled()) log.debug ("Ignoring header "+ responseheader.getName());
						ignoreHeader = true;
						break; //out of inner loop 
					}
				}
				if (!ignoreHeader) {
					filteredResponseheaders.append("\n");
					filteredResponseheaders.append(responseheader.getName() + ": "+ responseheader.getValue());
				} 
			}

			String responsebody = new String (msg.getResponseBody().getBytes());
			String [] responseparts = {filteredResponseheaders.toString(), responsebody};

			//try each of the patterns in turn against the response.				
			String timestampType = null;
			Iterator<Pattern> patternIterator = timestampPatterns.keySet().iterator();		

			while (patternIterator.hasNext()) {
				Pattern timestampPattern = patternIterator.next();
				timestampType = timestampPatterns.get(timestampPattern);
				if (log.isDebugEnabled()) log.debug("Trying Timestamp Pattern: "+ timestampPattern + " for timestamp type "+ timestampType);
				for (String haystack: responseparts) {
					Matcher matcher = timestampPattern.matcher(haystack);
					while (matcher.find()) {
						String evidence = matcher.group();
						java.util.Date timestamp=null;
						try {
							//parse the number as a Unix timestamp
							timestamp = new java.util.Date((long)Integer.parseInt(evidence) *1000);
						}
						catch (NumberFormatException nfe) {
							//the number is not formatted correctly to be a timestamp. Skip it.
							continue;
						}
						if (log.isDebugEnabled()) log.debug("Found a match for timestamp type "+ timestampType +":" + evidence);

						if ( evidence!=null && evidence.length() > 0) {
							//we found something.. potentially
							Alert alert = new Alert(getPluginId(), Alert.RISK_INFO, Alert.CONFIDENCE_LOW, getName() + " - "+ timestampType );
							alert.setDetail(
									getDescription() + " - "+ timestampType, 
									msg.getRequestHeader().getURI().toString(), 
									"", //param
									evidence, //TODO: this should be the the attack (NULL).  Set this field to NULL, once Zap allows mutiple alerts on the same URL, with just different evidence 
									getExtraInfo(msg, evidence, timestamp),  //other info
									getSolution(), 
									getReference(), 
									evidence,
									200, //Information Exposure, 
									13, //Information Leakage
									msg);  
							parent.raiseAlert(id, alert);
							//do NOT break at this point.. we need to find *all* the potential timestamps in the response..
						}
					}
				}	
			}
		} catch (URIException e) {
			log.error ("An exception occurrred passively scanning for timestamps");
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
		return 10096;
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
	private String getExtraInfo(HttpMessage msg, String evidence, Date timestamp) {		
		String formattedDate = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(timestamp);		
		return Constant.messages.getString(MESSAGE_PREFIX + "extrainfo", evidence, formattedDate);        
	}


}
