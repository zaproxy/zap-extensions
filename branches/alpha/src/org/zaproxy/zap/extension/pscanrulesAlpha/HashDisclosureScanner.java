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

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import net.htmlparser.jericho.Source;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;



/**
 * A class to passively scan responses known Hash signatures
 * @author 70pointer@gmail.com
 *
 */

public class HashDisclosureScanner extends PluginPassiveScanner {
	
	private PassiveScanThread parent = null;
	
	/**
	 * a map of a regular expression pattern to details of the Hash type found 
	 */
	static Map <Pattern, String> hashPatterns = new HashMap <Pattern, String> ();
	
	static {
		hashPatterns.put(Pattern.compile("\\b[0-9a-f]{128}\\b", Pattern.CASE_INSENSITIVE), "SHA-512");
		hashPatterns.put(Pattern.compile("\\b[0-9a-f]{96}\\b", Pattern.CASE_INSENSITIVE), "SHA-384");
		hashPatterns.put(Pattern.compile("\\b[0-9a-f]{64}\\b", Pattern.CASE_INSENSITIVE), "SHA-256");
		hashPatterns.put(Pattern.compile("\\b[0-9a-f]{56}\\b", Pattern.CASE_INSENSITIVE), "SHA-224");
		hashPatterns.put(Pattern.compile("\\b[0-9a-f]{40}\\b", Pattern.CASE_INSENSITIVE), "SHA-1");
		
		hashPatterns.put(Pattern.compile("\\b[0-9a-f]{32}\\b", Pattern.CASE_INSENSITIVE), "MD4 / MD5");
		
		hashPatterns.put(Pattern.compile("\\b\\$LM\\$[a-f0-9]{16}\\b", Pattern.CASE_INSENSITIVE), "LanMan / DES");
		hashPatterns.put(Pattern.compile("\\b\\$K4\\$[a-f0-9]{16},\\b", Pattern.CASE_INSENSITIVE), "Kerberos AFS DES");
		hashPatterns.put(Pattern.compile("\\b\\$2a\\$05\\$[a-zA-z0-9\\+\\-_./=]{53}\\b", Pattern.CASE_INSENSITIVE), "OpenBSD Blowfish");		
		hashPatterns.put(Pattern.compile("\\b\\$2y\\$05\\$[a-zA-z0-9\\+\\-_./=]{53}\\b", Pattern.CASE_INSENSITIVE), "OpenBSD Blowfish");
		
		//hashPatterns.put(Pattern.compile("\\b\\+[a-zA-Z0-9\\+\\-_./=]{12}\\b", Pattern.CASE_INSENSITIVE), "Eggdrop");  //too many false positives
				
		//DES Crypt
		//hashPatterns.put(Pattern.compile("\\b[./0-9A-Za-z]{13}\\b"),"DES Crypt");  //Way too many false positives.. 

		//BSDI Crypt
		//Example: _J9..K0AyUubDrfOgO4s
		//hashPatterns.put(Pattern.compile("\\b_[./0-9A-Za-z]{19}\\b", Pattern.CASE_INSENSITIVE), "BSDI Crypt");  //Way too many false positives..  

		//Example: qiyh4XPJGsOZ2MEAyLkfWqeQ
		//BigCrypt clashes with Crypt 16
		//hashPatterns.put(Pattern.compile("\\b[./0-9A-Za-z]{13}\\b", Pattern.CASE_INSENSITIVE), "BigCrypt");  //Way too many false positives..
		//hashPatterns.put(Pattern.compile("\\b[./0-9A-Za-z]{24}\\b", Pattern.CASE_INSENSITIVE), "BigCrypt");
		//hashPatterns.put(Pattern.compile("\\b[./0-9A-Za-z]{35}\\b", Pattern.CASE_INSENSITIVE), "BigCrypt");
		//hashPatterns.put(Pattern.compile("\\b[./0-9A-Za-z]{46}\\b", Pattern.CASE_INSENSITIVE), "BigCrypt");
		//hashPatterns.put(Pattern.compile("\\b[./0-9A-Za-z]{57}\\b", Pattern.CASE_INSENSITIVE), "BigCrypt");
		//hashPatterns.put(Pattern.compile("\\b[./0-9A-Za-z]{68}\\b", Pattern.CASE_INSENSITIVE), "BigCrypt");

		//Crypt 16 (clashes with BigCrypt)
		//Example: qi8H8R7OM4xMUNMPuRAZxlY.
		//hashPatterns.put(Pattern.compile("\\b[./0-9A-Za-z]{24}\\b"), "Crypt 16");   //too many false positives

		//MD5 Crypt 
		//Example: $1$O3JMY.Tw$AdLnLjQ/5jXF9.MTp3gHv/
		hashPatterns.put(Pattern.compile("\\b\\$1\\$[./0-9A-Za-z]{0,8}\\$[./0-9A-Za-z]{22}\\b"), "MD5 Crypt");

		//SHA-256 Crypt
		//Example: $5$MnfsQ4iN$ZMTppKN16y/tIsUYs/obHlhdP.Os80yXhTurpBMUbA5
		//Example: $5$rounds=5000$usesomesillystri$KqJWpanXZHKq2BOB43TSaYhEWsQ1Lr5QNyPCDH/Tp.6
		hashPatterns.put(Pattern.compile("\\b\\$5\\$[./0-9A-Za-z]{0,16}\\$[./0-9A-Za-z]{43}\\b"), "SHA-256 Crypt");
		hashPatterns.put(Pattern.compile("\\b\\$5\\$rounds=[0-9]+\\$[./0-9A-Za-z]{0,16}\\$[./0-9A-Za-z]{43}\\b"), "SHA-256 Crypt");

		//SHA-512 Crypt
		//Example: $6$zWwwXKNj$gLAOoZCjcr8p/.VgV/FkGC3NX7BsXys3KHYePfuIGMNjY83dVxugPYlxVg/evpcVEJLT/rSwZcDMlVVf/bhf.1
		//Example: $6$rounds=5000$usesomesillystri$D4IrlXatmP7rx3P3InaxBeoomnAihCKRVQP22JZ6EY47Wc6BkroIuUUBOov1i.S5KPgErtP/EN5mcO.ChWQW21
		hashPatterns.put(Pattern.compile("\\b\\$6\\$[./0-9A-Za-z]{0,16}\\$[./0-9A-Za-z]{86}\\b"), "SHA-512 Crypt");
		hashPatterns.put(Pattern.compile("\\b\\$6\\$rounds=[0-9]+\\$[./0-9A-Za-z]{0,16}\\$[./0-9A-Za-z]{86}\\b"), "SHA-512 Crypt");

		//BCrypt
		//Example: $2a$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe
		hashPatterns.put(Pattern.compile("\\b\\$2\\$[0-9]{2}\\$[./0-9A-Za-z]{53}\\b"), "BCrypt");
		hashPatterns.put(Pattern.compile("\\b\\$2a\\$[0-9]{2}\\$[./0-9A-Za-z]{53}\\b"), "BCrypt");

		//LanMan (clashes with MD4/MD5)
		//Example: 855c3697d9979e78ac404c4ba2c66533) 
		hashPatterns.put(Pattern.compile("\\b\\[0-9a-f]{32}\\b"), "LanMan");

		//NTLM
		//Example: $NT$7f8fe03093cc84b267b109625f6bbf4b		
		hashPatterns.put(Pattern.compile("\\b\\$3\\$\\$[0-9a-f]{32}\\b"), "NTLM");
		hashPatterns.put(Pattern.compile("\\b\\$NT\\$[0-9a-f]{32}\\b"), "NTLM");

		//Mac OS X salted SHA-1
		//Example: 0E6A48F765D0FFFFF6247FA80D748E615F91DD0C7431E4D9
		hashPatterns.put(Pattern.compile("\\b[0-9A-F]{48}\\b"), "Mac OSX salted SHA-1");
		
		//TODO: consider sorting the patterns by decreasing pattern length, so more specific patterns are tried before more general patterns
		//TODO: for the main hash types, verify the value by hashing the parameters
		//	if the hash value can be re-generated, then it is a "reflection" attack
		//  if the hash value cannot be re-generated using the available data, then perhaps it is being retrieved from a database???  => Dangerous.  
	}
	
	private static Logger log = Logger.getLogger(HashDisclosureScanner.class);

	/**
	 * Prefix for internationalized messages used by this rule
	 */
	private static final String MESSAGE_PREFIX = "pscanalpha.hashdisclosure.";

	/**
	 * construct the class, and register for i18n
	 */
	public HashDisclosureScanner() {
		super();
		PscanUtils.registerI18N();
	}

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
		//TODO: implement this as well! We may be generating a hash on the client side, and uploading it to the server.
	}

	/**
	 * scans the HTTP response for Hash signatures
	 * @param msg
	 * @param id
	 * @param source unused
	 */
	@Override
	public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
		
		if (log.isDebugEnabled()) log.debug("Checking message "+ msg + " for Hashes");
		
		//get the body contents as a String, so we can match against it
		String responseheader = msg.getResponseHeader().getHeadersAsString();
		String responsebody = new String (msg.getResponseBody().getBytes());
		String [] responseparts = {responseheader, responsebody};
		
		//try each of the patterns in turn against the response.				
		String hashType = null;
		Iterator<Pattern> patternIterator = hashPatterns.keySet().iterator();		
		
		while (patternIterator.hasNext()) {
			Pattern hashPattern = patternIterator.next();
			hashType = hashPatterns.get(hashPattern);
			if (log.isDebugEnabled()) log.debug("Trying Hash Pattern: "+ hashPattern + " for hash type "+ hashType);
			for (String haystack: responseparts) {
				Matcher matcher = hashPattern.matcher(haystack);
		        while (matcher.find()) {
		            String evidence = matcher.group();
		            if (log.isDebugEnabled()) log.debug("Found a match for hash type "+ hashType +":" + evidence);
		            
			        if ( evidence!=null && evidence.length() > 0) {
						//we found something
						Alert alert = new Alert(getId(), Alert.RISK_MEDIUM, Alert.WARNING, getName() + " - "+ hashType );
						alert.setDetail(
								getDescription() + " - "+ hashType, 
								msg.getRequestHeader().getURI().toString(), 
								"", //param
								evidence, //TODO: this should be the the attack (NULL).  Set this field to NULL, once Zap allows mutiple alerts on the same URL, with just different evidence 
								getExtraInfo(msg, evidence),  //other info
								getSolution(), 
								getReference(), 
								evidence,
								200, //Information Exposure, 
								13, //Information Leakage
								msg);  
						parent.raiseAlert(id, alert);
						//do NOT break at this point.. we need to find *all* the potential hashes in the response..
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
		return 10097;
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
	private String getExtraInfo(HttpMessage msg, String arg0) {		
		return Constant.messages.getString(MESSAGE_PREFIX + "extrainfo", arg0);        
	}


}
