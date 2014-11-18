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

package org.zaproxy.zap.extension.zest;

import javax.script.ScriptException;

import org.apache.commons.httpclient.HttpState;
import org.apache.commons.httpclient.cookie.CookiePolicy;
import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.ascan.ActiveScript;
import org.zaproxy.zap.extension.ascan.ScriptsActiveScanner;
import org.zaproxy.zap.users.User;

public class ZestActiveRunner extends ZestZapRunner implements ActiveScript {

	private ZestScriptWrapper script = null;
	private ScriptsActiveScanner sas = null;
	private HttpMessage msg = null;
	private String param = null;
	private ExtensionZest extension = null;

    private static Logger logger = Logger.getLogger(ZestActiveRunner.class);

	public ZestActiveRunner(ExtensionZest extension, ZestScriptWrapper script) {
		super(extension, script);
		this.extension = extension;
		this.script = script;
	}

	@Override
	public void scan(ScriptsActiveScanner sas, HttpMessage msg, String param, String value) throws ScriptException {
		logger.debug("Zest ActiveScan script: " + this.script.getName());
		this.sas = sas;
		this.msg = msg;
		this.param = param;

		try {
			sas.setParam(msg, param, "{{target}}");
			
			// We must handle the authentication "by hand" as the HttpRunner is not used (direct call to HttpClient)
			// when executing Zest scripts
			
			HttpSender sender = this.sas.getParent().getHttpSender();
			
			// Not sure is we do really need to revert to the original value.
			// Let's say yes for now
			String originalCookiePolicy = sender.getClient().getParams().getCookiePolicy();
			HttpState originalState = sender.getClient().getState();
			
			sender.getClient().getParams().setCookiePolicy(CookiePolicy.BROWSER_COMPATIBILITY);
			this.setHttpClient(sender.getClient());
			
			User forceUser = sender.getUser(msg);
			if (forceUser != null) {
				forceUser.processMessageToMatchUser(msg);
				sender.getClient().setState(forceUser.getCorrespondingHttpState());
			}
	
			this.run(script.getZestScript(), 
					ZestZapUtils.toZestRequest(msg, false, true, extension.getParam()), 
					null);
			
			// Restore previous values
			sender.getClient().getParams().setCookiePolicy(originalCookiePolicy);
			sender.getClient().setState(originalState);

			
		} catch (Exception e) {
			throw new ScriptException(e);
		}
	}

	@Override
	public void alertFound(Alert alert) {
		// Override this as we can put in more info from the script and message
		sas.raiseAlert(alert.getRisk(), alert.getReliability(), alert.getAlert(), script.getDescription(), 
				msg.getRequestHeader().getURI().toString(), param, "", "", "", "", -1, -1, msg);
	}
}
