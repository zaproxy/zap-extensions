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

import java.util.HashSet;
import java.util.LinkedList;
import java.util.Set;
import java.util.Vector;
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
 * A class to passively scan responses for indications of the use of insecure components
 * @author 70pointer@gmail.com
 *
 */
public class InsecureComponentScanner extends PluginPassiveScanner {

	/**
	 * a pattern for identifying module product and version
	 */
	private Pattern MODULE_PATTERN = Pattern.compile("([^ ]+)/([^ ]+)");

	/**
	 * a pattern for identifying and parsing the server header line (normal case)
	 */
	private Pattern SERVER_HEADER_PATTERN = Pattern.compile("^([^ ]+)/([^ ]+)(.*)$");

	/**
	 * used to match Oracle headers, since these are non-standard
	 */
	private Pattern SERVER_HEADER_PATTERN_ORACLE = Pattern.compile("^Oracle-Application-Server-[0-9]+[gi] ([^ ]+)/([^ ]+).*$");

	/**
	 * used to match Jetty headers, since these are non-standard
	 */
	private Pattern SERVER_HEADER_PATTERN_JETTY = Pattern.compile("^([^ ]+)\\(([^ ]+)\\).*$");

	/**
	 * used to match JBoss headers, since these are non-standard
	 */
	private Pattern SERVER_HEADER_PATTERN_JBOSS = Pattern.compile("^Servlet [^ ]+[ ]+(JBoss)-([^ /]+).*$");


	private PassiveScanThread parent = null;

	/**
	 * the logger. it logs stuff. 
	 */
	private static Logger log = Logger.getLogger(InsecureComponentScanner.class);


	/**
	 * Prefix for internationalized messages used by this rule
	 */
	private static final String MESSAGE_PREFIX = "pscanalpha.insecurecomponent.";

	/**
	 * construct the class, and register for i18n
	 */
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
		// do nothing
	}



	/**
	 * scans the HTTP response for insecure components
	 * @param msg
	 * @param id
	 * @param source unused
	 */
	@Override
	public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
		Vector <String> headerVector = new Vector <String>();

		Vector<String> serverHeaderVector = msg.getResponseHeader().getHeaders("Server");
		if ( serverHeaderVector!= null ) headerVector.addAll(serverHeaderVector); 
		Vector<String> poweredByHeaderVector = msg.getResponseHeader().getHeaders("X-Powered-By");
		if ( poweredByHeaderVector!= null ) headerVector.addAll(poweredByHeaderVector);

		//for each header (there could be multiple, or none)
		for (String header : headerVector) {
			if (header != null) {
				Set <Product> matchingProducts = new HashSet<Product> ();
				//per rfc2616, the server token can contain multiple product tokens, delimited by a space character
				//and each product token takes the form: "token" or "token/product-version".
				//in practice, we only see one of the following: 
				//1: <<Server>>
				//2: <<Server>>/<<version>>
				//3: <<Server>>/<<version>> (<<subcomponent>>)
				//4: <<Server>> (<<subcomponent>>)
				//we're only interested cases where we can see the version, or the subcomponent (since we can't do anything meaningful without a software version)
				//In the case of Apache, the subcomponent (if present) is the web server's underlying OS.  That's good to know :)

				VulnerabilityCache vc = VulnerabilityCache.getSingleton();					

				Matcher matcher = SERVER_HEADER_PATTERN.matcher(header);
				Matcher matcherOracle = SERVER_HEADER_PATTERN_ORACLE.matcher (header);					
				Matcher matcherJetty = SERVER_HEADER_PATTERN_JETTY.matcher (header);
				Matcher matcherJBoss = SERVER_HEADER_PATTERN_JBOSS.matcher(header);

				//for generic (mostly compliant with the rfc) products
				if (matcher.matches()) {
					String product = null, version = null, dregs = null;
					product = matcher.group(1);
					version = matcher.group(2);
					dregs = matcher.group(3);
					matchingProducts.add(new Product (Product.ProductType.PRODUCTTYPE_WEBSERVER, product, version));

					//look for Apache web server modules, if any
					if ( dregs!= null && dregs.length() > 0 && header.startsWith("Apache")) {
						for ( String potentialModule: dregs.split(" ")) {
							Matcher modulematcher = MODULE_PATTERN.matcher(potentialModule);
							if (modulematcher.matches()) {
								product = modulematcher.group(1);
								version = modulematcher.group(2);
								//remove the leading "v" in the version for the Apache Perl module (not for mod_perl though)
								if (product.equals("Perl")) version = version.replaceFirst("^v(.*)$", "$1");
								matchingProducts.add(new Product (Product.ProductType.PRODUCTTYPE_APACHE_MODULE, product, version));
							}
						}
					}
				}					
				//for Oracle webserver...
				while (matcherOracle.find()) { 
					String product = null, version = null;
					product = matcherOracle.group(1);
					version = matcherOracle.group(2);
					matchingProducts.add(new Product (Product.ProductType.PRODUCTTYPE_WEBSERVER, product, version));
				}
				//for Jetty
				while (matcherJetty.find()) { 
					String product = null, version = null;
					product = matcherJetty.group(1);
					version = matcherJetty.group(2);
					matchingProducts.add(new Product (Product.ProductType.PRODUCTTYPE_WEBSERVER, product, version));
				}
				//for JBoss
				while (matcherJBoss.find()) { 
					String product = null, version = null;
					product = matcherJBoss.group(1);
					version = matcherJBoss.group(2);
					matchingProducts.add(new Product (Product.ProductType.PRODUCTTYPE_WEBSERVER, product, version));
				}

				//for each of the product matches.
				for ( Product matchingProduct : matchingProducts) {						

					String product = matchingProduct.getProductName();
					String version = matchingProduct.getProductVersion();

					if ( product!= null && version != null) {
						//TODO: handle special cases of web server software here that does not follow rfc2616						
						if (log.isDebugEnabled()) log.debug("Found '"+product + "' version '"+ version+ "'");						
						LinkedList<CVE> vulnlist;
						try {
							//get the cached vulnerabilities (or retrieve them and cache them)
							vulnlist = vc.getVulnerabilities(matchingProduct);

							//if we found vulnerabilities, raise them (by throwing a single alert, using the highest risk noted)
							if (vulnlist != null && vulnlist.size() > 0) {
								if (log.isDebugEnabled()) log.debug("Found vulnerabilities");

								StringBuffer sb = new StringBuffer ();
								StringBuffer sbRefs = new StringBuffer ();
								Double highestCvss = null;
								boolean highestCVSSNoted = false;
								for (CVE cve : vulnlist) {
									if (!highestCVSSNoted) highestCvss = cve.getCvss();
									highestCVSSNoted = true;

									sb.append("CVE: "+ cve.getCve() + "\n");
									sb.append("CVSS: "+ cve.getCvss() + "\n\n");

									sbRefs.append("http://www.cvedetails.com/cve-details.php?cve_id=");
									sbRefs.append(cve.getCve() + "\n");
								}

								//now we have the list of vulnerabilities in string form, so raise the alert
								String extraInfo = new String (sb);
								String refs = new String (sbRefs);
								int cvssAlertLevel = 0;
								
								if (highestCvss< 2.5) {
									cvssAlertLevel = Alert.RISK_INFO;
								} else if (highestCvss< 5.0) {
									cvssAlertLevel = Alert.RISK_LOW;
								} else if (highestCvss< 7.5) {
									cvssAlertLevel = Alert.RISK_MEDIUM;
								} else cvssAlertLevel = Alert.RISK_HIGH;
								
								//lets go ahead and raise the alert
								Alert alert = new Alert(getPluginId(), cvssAlertLevel, Alert.WARNING, getName() + " - "+ product + " "+ version);
								alert.setDetail(
										Constant.messages.getString(MESSAGE_PREFIX + "desc", product, version, highestCvss, vulnlist.size()) , 
										msg.getRequestHeader().getURI().toString(), 
										"", //param
										"", //attack 
										extraInfo,  //other info
										Constant.messages.getString(MESSAGE_PREFIX + "soln", product, version), 
										Constant.messages.getString(MESSAGE_PREFIX + "refs", refs), 
										header,		//evidence	
										829,	//CWE 829: Inclusion of Functionality from Untrusted Control Sphere
										0,		//There is no CWE for "Components with Known Vulnerabilities!"
										msg);  
								parent.raiseAlert(id, alert);
							}
						} catch (Exception e) {
							log.error("Error getting the list of web server vulnerabilities", e);
						} 
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
	@Override
	public int getPluginId() {
		return 10046;
	}

}


