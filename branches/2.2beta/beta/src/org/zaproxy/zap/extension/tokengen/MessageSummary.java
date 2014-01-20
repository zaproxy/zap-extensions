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
package org.zaproxy.zap.extension.tokengen;

import org.parosproxy.paros.network.HttpMessage;

public class MessageSummary {

    private String method;
    private String uriString;
    private String statusCodeStr;
    private String reasonPhrase;
    private String timeElapsedMillis;
    private String lengthStr;
    private String token;

	public MessageSummary(HttpMessage msg) {
		this.method = msg.getRequestHeader().getMethod();
        this.uriString = msg.getRequestHeader().getURI().toString();
        this.statusCodeStr = Integer.toString(msg.getResponseHeader().getStatusCode());
        this.reasonPhrase = msg.getResponseHeader().getReasonPhrase();
        this.timeElapsedMillis = Integer.toString(msg.getTimeElapsedMillis());
        this.lengthStr = Integer.toString(msg.getResponseBody().toString().length());
        this.token = msg.getNote();        // The note is used to store the token 
	}

	public String getMethod() {
		return method;
	}

	public String getUriString() {
		return uriString;
	}

	public String getStatusCodeStr() {
		return statusCodeStr;
	}

	public String getReasonPhrase() {
		return reasonPhrase;
	}

	public String getTimeElapsedMillis() {
		return timeElapsedMillis;
	}

	public String getLengthStr() {
		return lengthStr;
	}

	public String getToken() {
		return token;
	}

    
}
