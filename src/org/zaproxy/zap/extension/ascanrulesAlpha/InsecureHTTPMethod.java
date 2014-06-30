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

import java.net.Socket;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.TreeSet;

import org.apache.commons.httpclient.ProxyClient;
import org.apache.commons.httpclient.ProxyClient.ConnectResponse;
import org.apache.commons.lang.RandomStringUtils;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

/**
* a scanner that looks for known insecure HTTP methods enabled for the URL
* Note that HTTP methods can be enabled for individual URLs, rather than necessarily just at host level
* It is also possible for methods to be actually be supported, without being documented by the OPTIONS method, so at High Attack Strength, check that as well (regardless of Threshold).  
* 
* @author 70pointer
*
*/
public class InsecureHTTPMethod extends AbstractAppPlugin {

	/**
	 * the set of methods that we know are unsafe.  There may be others.
	 */
	public static final List <String> INSECURE_METHODS = new LinkedList<String>(Arrays.asList(new String [] 
			{
			"TRACE",
			"TRACK",
			"CONNECT"
			}
			));
	
	/**
	 * details of the vulnerability which we are attempting to find 
	 * 45 = "Fingerprinting"
	 */
	private static final Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_45");

	/**
	 * the logger object
	 */
	private static final Logger log = Logger.getLogger(InsecureHTTPMethod.class);


	/**
	 * returns the plugin id
	 */
	@Override
	public int getId() {
		return 90028;
	}

	/**
	 * returns the name of the plugin
	 */
	@Override
	public String getName() {
		return Constant.messages.getString("ascanalpha.insecurehttpmethod.name");
	}

	@Override
	public String[] getDependency() {
		return null;
	}

	@Override
	public String getDescription() {
		if (vuln != null) {
			return vuln.getDescription();
		}
		return "Failed to load vulnerability description from file";
	}

	@Override
	public int getCategory() {
		return Category.SERVER;
	}

	@Override
	public String getSolution() {
		if (vuln != null) {
			return vuln.getSolution();
		}
		return "Failed to load vulnerability solution from file";
	}

	@Override
	public String getReference() {
		if (vuln != null) {
			StringBuilder sb = new StringBuilder();
			for (String ref : vuln.getReferences()) {
				if (sb.length() > 0) {
					sb.append('\n');
				}
				sb.append(ref);
			}
			return sb.toString();
		}
		return "Failed to load vulnerability reference from file";
	}

	@Override
	public void init() {		
	}


	@Override
	public void scan() {		
		try {
			String allowedmethods = null;
			String publicmethods = null;			
			String thirdpartyHost = "www.google.com";
			int thirdpartyPort = 80;			
			
			AttackStrength attackStrength = getAttackStrength();
			if (attackStrength == AttackStrength.HIGH || attackStrength == AttackStrength.INSANE) {
				//in this case, we do not bother with the OPTIONS method, but try all the insecure methods on the URL directly
				//this is useful in the case where the OPTIONS method does not report the method, but where it is actually supported
				//in this case, if a vulnerability is reported, there is little doubt that it is real
				//try the TRACK method
				MessageAndEvidence maeTrack = testTraceOrTrack(this.getBaseMsg(), "TRACK");
				if ( maeTrack != null) {
					bingo(	Alert.RISK_MEDIUM, 
							Alert.WARNING,
							Constant.messages.getString("ascanalpha.insecurehttpmethod.detailed.name", "TRACK"),
							Constant.messages.getString("ascanalpha.insecurehttpmethod.trace.exploitable.desc", "TRACK"), 
							null, // originalMessage.getRequestHeader().getURI().getURI(),
							null, // parameter being attacked: none.
							"",  // attack
							Constant.messages.getString("ascanalpha.insecurehttpmethod.trace.exploitable.extrainfo", maeTrack.evidence),
							Constant.messages.getString("ascanalpha.insecurehttpmethod.soln"),
							maeTrack.evidence,		//evidence, highlighted in the message
							maeTrack.message
							);
					}
				//try the TRACE method
				MessageAndEvidence maeTrace = testTraceOrTrack(this.getBaseMsg(), "TRACE");
				if ( maeTrace != null) {
					bingo(	Alert.RISK_MEDIUM, 
							Alert.WARNING,
							Constant.messages.getString("ascanalpha.insecurehttpmethod.detailed.name", "TRACE"),
							Constant.messages.getString("ascanalpha.insecurehttpmethod.trace.exploitable.desc", "TRACE"), 
							null, // originalMessage.getRequestHeader().getURI().getURI(),
							null, // parameter being attacked: none.
							"",  // attack
							Constant.messages.getString("ascanalpha.insecurehttpmethod.trace.exploitable.extrainfo", maeTrace.evidence),
							Constant.messages.getString("ascanalpha.insecurehttpmethod.soln"),
							maeTrace.evidence,		//evidence, highlighted in the message
							maeTrace.message
							);
					}
				
				//use a CONNECT method to try establish a socket connection to a third party, via the server being tested
				boolean connectWorks = testConnect (this.getBaseMsg(), thirdpartyHost, thirdpartyPort);
				if (connectWorks) {
					bingo(	Alert.RISK_MEDIUM, 
							Alert.WARNING,
							Constant.messages.getString("ascanalpha.insecurehttpmethod.detailed.name", "CONNECT"),
							Constant.messages.getString("ascanalpha.insecurehttpmethod.connect.exploitable.desc", "CONNECT"), 
							null, // originalMessage.getRequestHeader().getURI().getURI(),
							null, // parameter being attacked: none.
							"",  // attack
							Constant.messages.getString("ascanalpha.insecurehttpmethod.connect.exploitable.extrainfo", thirdpartyHost),
							Constant.messages.getString("ascanalpha.insecurehttpmethod.soln"),
							"",		//evidence, highlighted in the message
							this.getBaseMsg()
							);
				}
			} 
			
			if (attackStrength != AttackStrength.HIGH && attackStrength != AttackStrength.INSANE) {
				//send an OPTIONS message, and see what the server reports.  Do not try any methods not listed in those results.
				HttpMessage optionsmsg = getNewMsg();		
				HttpRequestHeader optionsRequestHeader = this.getBaseMsg().getRequestHeader();
				optionsRequestHeader.setMethod(HttpRequestHeader.OPTIONS);
				optionsRequestHeader.setVersion(HttpRequestHeader.HTTP11);  //OPTIONS is not supported in 1.0
				optionsmsg.setRequestHeader(optionsRequestHeader);
				
				sendAndReceive(optionsmsg, false); //do not follow redirects
				
				//TODO: use HttpHeader.METHODS_ALLOW and HttpHeader.METHODS_PUBLIC, once this change is in the core. 
				allowedmethods = optionsmsg.getResponseHeader().getHeader("Allow");			
				publicmethods = optionsmsg.getResponseHeader().getHeader("Public");
				
				/*
				//DEBUG only, to test the CONNECT method against a Squid instance, which does not support OPTIONS.
				//TODO: need to test for these insecure methods, even if the OPTIONS method did not indicate that the method is supported
				//ie, test for hidden/masked support for these insecure methods, as well as documented support.
				log.error("Setting the allowed methods to 'CONNECT'");
				allowedmethods = "CONNECT";
				publicmethods = null;
				*/
				
				if ( log.isDebugEnabled() ) {
					log.debug("allowedmethods: "+allowedmethods);
					log.debug("publicmethods: "+publicmethods);
					}
				
				if ( allowedmethods == null) {
					//nothing to see here. Move along now.				
					return;
				}
				//if the "Public" response is present (for IIS), use that to determine the enabled methods.
				if ( publicmethods != null) {
					allowedmethods = publicmethods;
				}
			
				//rely on the OPTIONS METHOD, but potentially verify the results, depending on the Threshold.
				for (String enabledmethod: allowedmethods.toUpperCase().split(",")) {
					enabledmethod = enabledmethod.trim();  //strip off any leading spaces (it happens!)
					
					if (log.isDebugEnabled ()) log.debug("The following enabled method is being checked: '"+ enabledmethod  + "'");
					
					for (String insecureMethod : INSECURE_METHODS) {
						if (enabledmethod.equals(insecureMethod)) {
							String evidence = null;
							HttpMessage alertMessage = optionsmsg;
							String extraInfo = null;
							String description = null;
							
							//if the threshold is Medium or above, then we need to confirm the vulnerability before alerting
							boolean raiseAlert = false;
							AlertThreshold threshold = getAlertThreshold();
							if (threshold != AlertThreshold.LOW ) {
								//!= Low threshold --> verify it
								if (enabledmethod.equals ("TRACE") || enabledmethod.equals ("TRACK")) {
									if (log.isDebugEnabled ())  log.debug("Verifying a TRACE/TRACK");								
									MessageAndEvidence mae = testTraceOrTrack(this.getBaseMsg(), enabledmethod);
									if ( mae != null) {
										evidence = mae.evidence;
										alertMessage = mae.message;
										raiseAlert = true;
										description = Constant.messages.getString("ascanalpha.insecurehttpmethod.trace.exploitable.desc", enabledmethod);
										extraInfo = Constant.messages.getString("ascanalpha.insecurehttpmethod.trace.exploitable.extrainfo", evidence);
									}								
								} else if (enabledmethod.equals ("CONNECT")) {
									
									if (log.isDebugEnabled ())  log.debug("Verifying a CONNECT");
																		
									//use a CONNECT method to establish a socket connection to a third party, via the server being tested
									boolean connectWorks = testConnect (this.getBaseMsg(), thirdpartyHost, thirdpartyPort);
									if (connectWorks) {
										evidence = "";
										alertMessage = optionsmsg;  //there is no connectmessage, since the HttpSender does not support CONNECT
										raiseAlert = true;
										description = Constant.messages.getString("ascanalpha.insecurehttpmethod.connect.exploitable.desc", enabledmethod);
										extraInfo = Constant.messages.getString("ascanalpha.insecurehttpmethod.connect.exploitable.extrainfo", thirdpartyHost);
									}
								} else {
									throw new Exception ("Cannot verify unrecognised HTTP method '"+ enabledmethod+ "'");
								}
							
							} else {
								//== Low threshold --> no need to verify it							
								evidence = enabledmethod;
								alertMessage = optionsmsg;
								raiseAlert = true;
								description = Constant.messages.getString("ascanalpha.insecurehttpmethod.desc", enabledmethod);
								extraInfo = Constant.messages.getString("ascanalpha.insecurehttpmethod.extrainfo", allowedmethods);
							}							
								 						
							if (raiseAlert ) {
								if ( log.isDebugEnabled() ) {
									log.debug("Raising alert for Insecure HTTP Method");
								}
								//bingo.
								bingo(	Alert.RISK_MEDIUM, 
									Alert.WARNING,
									Constant.messages.getString("ascanalpha.insecurehttpmethod.detailed.name", insecureMethod),
									description, 
									null, // originalMessage.getRequestHeader().getURI().getURI(),
									null, // parameter being attacked: none.
									"",  // attack
									extraInfo,
									Constant.messages.getString("ascanalpha.insecurehttpmethod.soln"),
									evidence,		//evidence, highlighted in the message
									alertMessage
									);
							}
						} else {
							if ( log.isDebugEnabled() ) {
								log.debug(enabledmethod + "!="+insecureMethod);
							}
						}
					}
				}
			}
		} catch (Exception e) {
			log.error("Error scanning a Host for Insecure HTTP Methods: " + e.getMessage(), e);
		}
		
	}

	@Override
	public int getRisk() {
		return Alert.RISK_MEDIUM; 
	}

	@Override
	public int getCweId() {
		return 200;  // Information Exposure (primarily via TRACK / TRACE)
	}

	@Override
	public int getWascId() {
		return 45;  //Fingerprinting
	}
	
	private class MessageAndEvidence {
		public HttpMessage message;
		public String evidence;
		
		public MessageAndEvidence (HttpMessage message, String evidence) {
			this.message = message;
			this.evidence = evidence;
		}
	}
	
	private MessageAndEvidence testTraceOrTrack(HttpMessage baseMsg, String method) throws Exception {
		HttpRequestHeader traceRequestHeader = baseMsg.getRequestHeader();								
		traceRequestHeader.setMethod(method);
		//TRACE is supported in 1.0. TRACK is presumably the same, since it is a alias for TRACE. Typical Microsoft.
		traceRequestHeader.setVersion(HttpRequestHeader.HTTP10);
		
		HttpMessage tracemsg = getNewMsg();
		tracemsg.setRequestHeader(traceRequestHeader);								
		String randomcookiename=RandomStringUtils.random(10, "abcdefghijklmoopqrstuvwxyz9123456789");
		String randomcookievalue=RandomStringUtils.random(40, "abcdefghijklmoopqrstuvwxyz9123456789");
		TreeSet<HtmlParameter> cookies = tracemsg.getCookieParams();
		cookies.add(new HtmlParameter(HtmlParameter.Type.cookie, randomcookiename, randomcookievalue));
		tracemsg.setCookieParams(cookies);
		
		sendAndReceive(tracemsg, false); //do not follow redirects. That might ruin our day.
		//if the response *body* from the TRACE request contains the cookie, we're in business :)
		if (tracemsg.getResponseBody().toString().contains(randomcookievalue)) {
			return new MessageAndEvidence(tracemsg, randomcookievalue);
		} else 
			return null;
	}
	
	private boolean testConnect (HttpMessage baseMsg, String thirdpartyHost, int thirdpartyPort) throws Exception {
		String connecthost = baseMsg.getRequestHeader().getURI().getHost();
		int connectport = baseMsg.getRequestHeader().getURI().getPort();
		 
		//this cannot currently be done using the existing HttpSender class, so do it natively using HttpClient, 
		//in as simple as possible a manner.
		Socket socket = null;
		try {
			ProxyClient client = new ProxyClient();								
			client.getHostConfiguration().setProxy(connecthost,connectport);								
			client.getHostConfiguration().setHost(thirdpartyHost,thirdpartyPort);
			ConnectResponse connectResponse = client.connect();
			socket = connectResponse.getSocket();
			if ( socket == null) {
				if (log.isDebugEnabled()) log.debug ("Could not establish a socket connection to a third party using the CONNECT HTTP method: NULL socket returned");
				return false;
			} else {
				if (log.isDebugEnabled()) log.debug("Raw Socket established to "+thirdpartyHost);
				socket.close();
				return true;
			}
		}
		catch (Exception e) {
			if (log.isDebugEnabled()) log.debug ("Could not establish a socket connection to a third party using the CONNECT HTTP method", e);
		}
		return false;
	}

}
