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
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
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
public class ShellShockScanner extends AbstractAppPlugin {

	/**
	 * the logger object
	 */
	private static final Logger log = Logger.getLogger(ShellShockScanner.class);


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
	public void scan() {		
		try {
			// First try a simple reflected attack
			HttpMessage msg = getNewMsg();
			String evidence = "ZAP-Vulnerable";
			String attack = "() { :;}; echo 'ShellShock: " + evidence + "'";
			msg.getRequestHeader().setHeader(HttpHeader.USER_AGENT, attack);
			sendAndReceive(msg, false); //do not follow redirects
			
			Vector<String> ssHeaders = msg.getResponseHeader().getHeaders("ShellShock");
			if (ssHeaders.size() > 0) {
				if (ssHeaders.get(0).contains(evidence)) {
					bingo(	getRisk(), 
							Alert.WARNING,
							this.getName(),
							this.getDescription(), 
							null, // originalMessage.getRequestHeader().getURI().getURI(),
							HttpHeader.USER_AGENT, // parameter being attacked
							attack,
							Constant.messages.getString("ascanalpha.shellshock.extrainfo"),
							this.getSolution(),
							evidence,
							msg
							);
					return;
				}
			}
			// Then a timing attack
			boolean vulnerable = false;
			msg = getNewMsg();
			attack = "() { :;}; sleep 5 ";
			msg.getRequestHeader().setHeader(HttpHeader.USER_AGENT, attack);
			sendAndReceive(msg, false); //do not follow redirects
			
			if (msg.getTimeElapsedMillis() > 5000) {
				vulnerable = true;
		        if (!Plugin.AlertThreshold.LOW.equals(this.getAlertThreshold()) && msg.getTimeElapsedMillis() > 6000) {
					// Could be that the server is overloaded, try a safe request
					HttpMessage safeMsg = getNewMsg();
					sendAndReceive(safeMsg, false); //do not follow redirects
					if (msg.getTimeElapsedMillis() > 5000) {
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
						HttpHeader.USER_AGENT, // parameter being attacked
						attack,
						Constant.messages.getString("ascanalpha.shellshock.extrainfo"),
						this.getSolution(),
						null,	// There isnt a relevant string to show
						msg
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
