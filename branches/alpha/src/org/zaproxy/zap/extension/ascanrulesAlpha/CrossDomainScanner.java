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

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.commons.httpclient.URI;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractHostPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * A class to actively check if the web server is configured to allow Cross Domain access, from a malicious 
 * third party service, for instance. Currently checks for wildcards in Adobe's crossdomain.xml. 
 * TODO: check for SilverLight's clientaccesspolicy.xml 
 * 
 * @author 70pointer
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
			
			//retrieve the file
			HttpMessage crossdomainmessage= new HttpMessage (new URI(originalURI.getScheme(), originalURI.getAuthority(), "/"+ADOBE_CROSS_DOMAIN_POLICY_FILE, null, null));
			sendAndReceive(crossdomainmessage, false);
			byte [] crossdomainmessagebytes = crossdomainmessage.getResponseBody().getBytes();
			
			//parse the file. If it's not parseable, it might have been because of a 404
			DocumentBuilderFactory docBuilderFactory;
			DocumentBuilder docBuilder;
			Document xmldoc;
			try {
				docBuilderFactory = DocumentBuilderFactory.newInstance();
				docBuilder = docBuilderFactory.newDocumentBuilder();
				//work around the "no protocol" issue by wrapping the content in a ByteArrayInputStream
				xmldoc = docBuilder.parse(new InputSource(new ByteArrayInputStream(crossdomainmessagebytes)));
				
				NodeList nodelist = xmldoc.getElementsByTagName("cross-domain-policy");				
				for ( int i=0; i< nodelist.getLength(); i++) {
					Node policyNode = nodelist.item(i);
					NodeList policyChildNodes  = policyNode.getChildNodes();
					for ( int j = 0; j < policyChildNodes.getLength(); j++) {
						//for each child node of cross-domain-policy
						Node policyChildNode = policyChildNodes.item(j);
						String nodeName = policyChildNode.getNodeName();
						if ( nodeName == null) {
							continue; //to the next node..
						} else if (nodeName.equals ("allow-access-from")) {
							//are "data load" (read) requests allowed from components hosted on arbitrary third party sites?
							//TODO: also raise alert if too many "allow-access-from" domains are allowed? (even if not wildcarded)							
							NamedNodeMap policyChildNodeAttribs = policyChildNode.getAttributes();
							for (int k = 0; k < policyChildNodeAttribs.getLength(); k++) {
								//for each attribute of cross-domain-policy >> allow-access-from
								Node policyChildNodeAttribute = policyChildNodeAttribs.item(k);
								if ( policyChildNodeAttribute.getNodeName().equals("domain")) {									
									String domainValue = policyChildNodeAttribute.getNodeValue();
									if ( domainValue.equals("*")) {
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
							}							
						} else if (nodeName.equals ("allow-http-request-headers-from")) {
							//are send requests allowed from components hosted on arbitrary third party sites? 
							NamedNodeMap policyChildNodeAttribs = policyChildNode.getAttributes();
							for (int k = 0; k < policyChildNodeAttribs.getLength(); k++) {
								//for each attribute of cross-domain-policy >> allow-access-from
								Node policyChildNodeAttribute = policyChildNodeAttribs.item(k);
								if ( policyChildNodeAttribute.getNodeName().equals("domain")) {									
									String domainValue = policyChildNodeAttribute.getNodeValue();
									if ( domainValue.equals("*")) {
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
							}
						}
					}
				}			
			
			} catch (SAXException | IOException e) {
				log.error("An error occurred trying to parse "+ADOBE_CROSS_DOMAIN_POLICY_FILE+" as XML: "+ e);
				return;
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
