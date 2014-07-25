/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
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

import java.io.ByteArrayInputStream;
import java.io.IOException;


import org.apache.commons.httpclient.URI;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractHostPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import javax.xml.xpath.*;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPathFactory;


/**
 * A class to actively check if the web server is configured to allow Cross Domain access, from a malicious 
 * third party service, for instance. Currently checks for wildcards in Adobe's crossdomain.xml, and in 
 * SilverLight's clientaccesspolicy.xml 
 * 
 * @author 70pointer@gmail.com
 *
 */
public class CrossDomainScanner extends AbstractHostPlugin {
	
	/**
	 * the logger object
	 */
	private static Logger log = Logger.getLogger(CrossDomainScanner.class);

	/**
	 * Prefix for internationalized messages used by this rule
	 */
	private static final String MESSAGE_PREFIX = "ascanalpha.crossdomain.";
	private static final String MESSAGE_PREFIX_ADOBE = "ascanalpha.crossdomain.adobe.";
	private static final String MESSAGE_PREFIX_ADOBE_READ = "ascanalpha.crossdomain.adobe.read.";
	private static final String MESSAGE_PREFIX_ADOBE_SEND = "ascanalpha.crossdomain.adobe.send.";
	private static final String MESSAGE_PREFIX_SILVERLIGHT = "ascanalpha.crossdomain.silverlight.";

	/**
	 * Adobe's cross domain policy file name
	 */
	static final String ADOBE_CROSS_DOMAIN_POLICY_FILE = "crossdomain.xml";
	
	/**
	 * Silverlight's cross domain policy file name
	 */
	static final String SILVERLIGHT_CROSS_DOMAIN_POLICY_FILE = "clientaccesspolicy.xml";

	/**
	 * returns the plugin id
	 */
	@Override
	public int getId() {
		return 20016;
	}

	/**
	 * returns the name of the plugin
	 */
	@Override
	public String getName() {
		return Constant.messages.getString(MESSAGE_PREFIX + "name");
	}

	@Override
	public String[] getDependency() {
		return null;
	}

	@Override
	public String getDescription() {
		return Constant.messages.getString(MESSAGE_PREFIX + "desc");
	}

	@Override
	public int getCategory() {
		return Category.SERVER;
	}

	@Override
	public String getSolution() {
		return Constant.messages.getString(MESSAGE_PREFIX + "soln");
	}

	@Override
	public String getReference() {
		return Constant.messages.getString(MESSAGE_PREFIX + "refs");
	}
	
	@Override
	public void init() {
	}

	/**
	 * scans the node for cross-domain mis-configurations
	 */
	@Override
	public void scan() {

		try {
			//get the network details for the attack
			URI originalURI = this.getBaseMsg().getRequestHeader().getURI();
			
			//retrieve the Adobe cross domain policy file, and assess it
			HttpMessage crossdomainmessage= new HttpMessage (new URI(originalURI.getScheme(), originalURI.getAuthority(), "/"+ADOBE_CROSS_DOMAIN_POLICY_FILE, null, null));
			sendAndReceive(crossdomainmessage, false);
			byte [] crossdomainmessagebytes = crossdomainmessage.getResponseBody().getBytes();
			
			//parse the file. If it's not parseable, it might have been because of a 404
			DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();;
			DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();;
			XPath xpath = (XPath) XPathFactory.newInstance().newXPath();
				
			try {
				//work around the "no protocol" issue by wrapping the content in a ByteArrayInputStream
				Document adobeXmldoc = docBuilder.parse(new InputSource(new ByteArrayInputStream(crossdomainmessagebytes)));
				
				//check for cross domain read (data load) access
				XPathExpression exprAllowAccessFromDomain = xpath.compile("/cross-domain-policy/allow-access-from/@domain"); 	//gets the domain attributes
				NodeList exprAllowAccessFromDomainNodes = (NodeList) exprAllowAccessFromDomain.evaluate(adobeXmldoc, XPathConstants.NODESET);
			    for (int i = 0; i < exprAllowAccessFromDomainNodes.getLength(); i++) {
			    	String domain = exprAllowAccessFromDomainNodes.item(i).getNodeValue();
			    	if ( domain.equals("*")) {
						//oh dear me.
						if (log.isInfoEnabled()) log.info("Bingo!  <allow-access-from domain=\"*\"");
						bingo(	getRisk(), 
								Alert.WARNING,
								Constant.messages.getString(MESSAGE_PREFIX_ADOBE_READ + "name"),
								Constant.messages.getString(MESSAGE_PREFIX_ADOBE + "desc"), 
								crossdomainmessage.getRequestHeader().getURI().getURI(), //the url field 
								"", //parameter being attacked: none.
								"", //attack
								Constant.messages.getString(MESSAGE_PREFIX_ADOBE_READ+ "extrainfo", "/"+ADOBE_CROSS_DOMAIN_POLICY_FILE),  //extrainfo
								Constant.messages.getString(MESSAGE_PREFIX_ADOBE_READ +"soln"),  //solution
								"<allow-access-from domain=\"*\"" ,     // evidence
								crossdomainmessage   //the message on which to place the alert
								);
					}
			    }
			    //check for cross domain send (upload) access
		    	XPathExpression exprRequestHeadersFromDomain = xpath.compile("/cross-domain-policy/allow-http-request-headers-from/@domain"); 	//gets the domain attributes
		    	NodeList exprRequestHeadersFromDomainNodes = (NodeList) exprRequestHeadersFromDomain.evaluate(adobeXmldoc, XPathConstants.NODESET);
			    for (int i = 0; i < exprRequestHeadersFromDomainNodes.getLength(); i++) {
			    	String domain = exprRequestHeadersFromDomainNodes.item(i).getNodeValue();
			    	if ( domain.equals("*")) {
						//oh dear, dear me.
						if (log.isInfoEnabled()) log.info("Bingo!  <allow-http-request-headers-from domain=\"*\"");
						bingo(	getRisk(), 
								Alert.WARNING,
								Constant.messages.getString(MESSAGE_PREFIX_ADOBE_SEND + "name"),
								Constant.messages.getString(MESSAGE_PREFIX_ADOBE + "desc"), 
								crossdomainmessage.getRequestHeader().getURI().getURI(), //the url field 
								"", //parameter being attacked: none.
								"", //attack
								Constant.messages.getString(MESSAGE_PREFIX_ADOBE_SEND+ "extrainfo", "/"+ADOBE_CROSS_DOMAIN_POLICY_FILE),  //extrainfo
								Constant.messages.getString(MESSAGE_PREFIX_ADOBE_SEND +"soln"),  //solution
								"<allow-http-request-headers-from domain=\"*\"" ,     // evidence
								crossdomainmessage   //the message on which to place the alert
								);
					}
			    }			
			} catch (SAXException | IOException e) {
				log.error("An error occurred trying to parse "+ADOBE_CROSS_DOMAIN_POLICY_FILE+" as XML: "+ e);
			}
			

			//retrieve the Silverlight client access policy file, and assess it.
			HttpMessage clientaccesspolicymessage= new HttpMessage (new URI(originalURI.getScheme(), originalURI.getAuthority(), "/"+SILVERLIGHT_CROSS_DOMAIN_POLICY_FILE, null, null));
			sendAndReceive(clientaccesspolicymessage, false);
			byte [] clientaccesspolicymessagebytes = clientaccesspolicymessage.getResponseBody().getBytes();
			
			//parse the file. If it's not parseable, it might have been because of a 404			
			try {
				//work around the "no protocol" issue by wrapping the content in a ByteArrayInputStream
				Document silverlightXmldoc = docBuilder.parse(new InputSource(new ByteArrayInputStream(clientaccesspolicymessagebytes)));				
				XPathExpression exprAllowFromUri = xpath.compile("/access-policy/cross-domain-access/policy/allow-from/domain/@uri"); 	//gets the uri attributes
				//check the "allow-from" policies
				NodeList exprAllowFromUriNodes = (NodeList) exprAllowFromUri.evaluate(silverlightXmldoc, XPathConstants.NODESET);
			    for (int i = 0; i < exprAllowFromUriNodes.getLength(); i++) {
			    	String uri = exprAllowFromUriNodes.item(i).getNodeValue();
			    	if (uri.equals ("*")) {
			    		//tut, tut, tut.
						if (log.isInfoEnabled()) log.info("Bingo! "+SILVERLIGHT_CROSS_DOMAIN_POLICY_FILE+", at /access-policy/cross-domain-access/policy/allow-from/domain/@uri");
						bingo(	getRisk(), 
								Alert.WARNING,
								Constant.messages.getString(MESSAGE_PREFIX_SILVERLIGHT + "name"),
								Constant.messages.getString(MESSAGE_PREFIX_SILVERLIGHT + "desc"), 
								clientaccesspolicymessage.getRequestHeader().getURI().getURI(), //the url field 
								"", //parameter being attacked: none.
								"", //attack
								Constant.messages.getString(MESSAGE_PREFIX_SILVERLIGHT+ "extrainfo"),  //extrainfo
								Constant.messages.getString(MESSAGE_PREFIX_SILVERLIGHT +"soln"),  //solution
								"<domain uri=\"*\"" ,     // evidence
								clientaccesspolicymessage   //the message on which to place the alert
								);
			    	}
			    }			    
			
			} catch (SAXException | IOException e) {
				log.error("An error occurred trying to parse "+SILVERLIGHT_CROSS_DOMAIN_POLICY_FILE+" as XML: "+ e);
			}

			
		} catch (Exception e) {
			//needed to catch exceptions from the "finally" statement 
			log.error("Error scanning a node for Cross Domain misconfigurations: " + e.getMessage(), e);
		}
	}

	@Override
	public int getRisk() {
		return Alert.RISK_HIGH; 
	}

	@Override
	public int getCweId() {
		return 264;  //CWE 264: Permissions, Privileges, and Access Controls
					//the more specific CWE's under this one are not rally relevant
	}

	@Override
	public int getWascId() {
		return 14; //WASC-14: Server Misconfiguration
	}

}
