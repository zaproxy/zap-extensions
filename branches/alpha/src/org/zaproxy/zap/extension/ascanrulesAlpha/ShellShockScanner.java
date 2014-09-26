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

import java.util.Vector;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;

/**
* a scanner that looks for servers vulnerable to ShellShock  
* 
* @author psiinon
*
*/
public class ShellShockScanner extends AbstractAppParamPlugin {

	/**
	 * the logger object
	 */
	private static final Logger log = Logger.getLogger(ShellShockScanner.class);
	
	private final String attackHeader = "X-Powered-By";		
	
	// Use a standard HTTP response header, to make sure the header is not dropped by load balancers, proxies, etc
	private final String evidence = "ShellShock-Vulnerable";

	/**
	 * returns the plugin id
	 */
	@Override
	public int getId() {
		return 10048;
	}

	/**
	 * returns the name of the plugin
	 */
	@Override
	public String getName() {
		return Constant.messages.getString("ascanalpha.shellshock.name");
	}

	@Override
	public String[] getDependency() {
		return null;
	}

	@Override
	public String getDescription() {
		return Constant.messages.getString("ascanalpha.shellshock.desc");
	}

	@Override
	public int getCategory() {
		return Category.SERVER;
	}

	@Override
	public String getSolution() {
		return Constant.messages.getString("ascanalpha.shellshock.soln");
	}

	@Override
	public String getReference() {
		return Constant.messages.getString("ascanalpha.shellshock.ref");
	}

	@Override
	public void init() {		
	}

	@Override	
	public void scan(HttpMessage origMsg, String paramName, String paramValue) {
		try {
			// First try a simple reflected attack
			// With CGI, the evidence will come out in the header
			HttpMessage msg1 = getNewMsg();
			String attack = "() { :;}; echo '"+attackHeader+": " + evidence + "'";
			
			setParameter (msg1, paramName, attack);
			sendAndReceive(msg1, false); //do not follow redirects
			
			
			Vector<String> ssHeaders = msg1.getResponseHeader().getHeaders(attackHeader);
			if (ssHeaders != null && ssHeaders.size() > 0) {
				for ( String header: ssHeaders) {
					if (header.contains(evidence)) {
						bingo(	getRisk(), 
								Alert.WARNING,
								this.getName(),
								this.getDescription(), 
								null, // originalMessage.getRequestHeader().getURI().getURI(),
								paramName, // parameter being attacked
								attack,
								Constant.messages.getString("ascanalpha.shellshock.extrainfo"),
								this.getSolution(),
								evidence,
								msg1
								);
						return;
					}	
				}
			}
			
			// Then a timing attack
			// With PHP, the evidence will come out in the body (this will be caught by the timing based attack)
			boolean vulnerable = false;
			HttpMessage msg2 = getNewMsg();
			attack = "() { :;}; /bin/sleep 5";
			
			setParameter(msg2, paramName, attack);
			sendAndReceive(msg2, false); //do not follow redirects
			long attackElapsedTime = msg2.getTimeElapsedMillis();
			
			if (attackElapsedTime > 5000) {
				vulnerable = true;
		        if (!Plugin.AlertThreshold.LOW.equals(this.getAlertThreshold()) && attackElapsedTime > 6000) {
					// Could be that the server is overloaded, try a safe request
					HttpMessage safeMsg = getNewMsg();
					sendAndReceive(safeMsg, false); //do not follow redirects
					if (safeMsg.getTimeElapsedMillis() > 5000 && 
							(safeMsg.getTimeElapsedMillis() - attackElapsedTime) < 5000) {
						// Looks like the server is just overloaded
						vulnerable = false;
					}
				}
			}
			if (vulnerable) {
				bingo(	getRisk(), 
						Alert.WARNING,
						this.getName(),
						this.getDescription(), 
						null, // originalMessage.getRequestHeader().getURI().getURI(),
						paramName, // parameter being attacked
						attack,
						Constant.messages.getString("ascanalpha.shellshock.extrainfo"),
						this.getSolution(),
						Constant.messages.getString("ascanalpha.shellshock.timingbased.evidence", attackElapsedTime),
						msg2
						);
				return;
			}

		} catch (Exception e) {
			log.error("Error scanning a Host for ShellShock: " + e.getMessage(), e);
		}
		
	}

	@Override
	public int getRisk() {
		return Alert.RISK_HIGH; 
	}

	@Override
	public int getCweId() {
		return 78;  // Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
	}

	@Override
	public int getWascId() {
		return 31;  // OS Commanding
	}

}
