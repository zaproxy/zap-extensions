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

import java.util.Map;

import javax.script.ScriptException;

import org.apache.commons.httpclient.URI;
import org.mozilla.zest.core.v1.ZestVariables;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.authentication.AuthenticationHelper;
import org.zaproxy.zap.authentication.GenericAuthenticationCredentials;
import org.zaproxy.zap.authentication.ScriptBasedAuthenticationMethodType.AuthenticationScript;

public class ZestAuthenticationRunner extends ZestZapRunner implements AuthenticationScript {

	private ZestScriptWrapper script = null;
	
	public ZestAuthenticationRunner(ExtensionZest extension, ZestScriptWrapper script) {
		super(extension, script);
		this.script = script;
	}

	@Override
	public String[] getRequiredParamsNames() {
		return new String[] {"LoginURL", "Method"};
	}

	@Override
	public String[] getOptionalParamsNames() {
		return new String[] {};
	}

	@Override
	public String[] getCredentialsParamsNames() {
		return new String[] {"Username", "Password"};
	}

	@Override
	public HttpMessage authenticate(AuthenticationHelper helper,
			Map<String, String> paramsValues,
			GenericAuthenticationCredentials credentials) throws ScriptException {
		
		try {
			paramsValues.put("Username", credentials.getParam("Username"));
			paramsValues.put("Password", credentials.getParam("Password"));

			this.run(script.getZestScript(), paramsValues);
			
			String respUrl = this.getVariable(ZestVariables.RESPONSE_URL);
			HttpMessage msg = new HttpMessage(new URI(respUrl, true));
			msg.setRequestHeader(
					this.getVariable(ZestVariables.REQUEST_METHOD) + " " +
						this.getVariable(ZestVariables.REQUEST_URL) + " " + 
							msg.getRequestHeader().getVersion() + HttpHeader.CRLF + 
								this.getVariable(ZestVariables.REQUEST_HEADER));
			msg.setRequestBody(this.getVariable(ZestVariables.REQUEST_BODY));
			msg.setResponseHeader(this.getVariable(ZestVariables.RESPONSE_HEADER));
			msg.setResponseBody(this.getVariable(ZestVariables.RESPONSE_BODY));

			return msg;
			
		} catch (Exception e) {
			throw new ScriptException(e);
		}
	}
}
