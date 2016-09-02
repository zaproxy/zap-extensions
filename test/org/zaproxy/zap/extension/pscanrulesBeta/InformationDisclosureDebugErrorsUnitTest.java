/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2016 The ZAP Development Team
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.pscanrulesBeta;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;

import org.junit.Test;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

public class InformationDisclosureDebugErrorsUnitTest extends PassiveScannerTest {
	private static final String URI = "https://www.example.com/";
	
	@Override
	protected InformationDisclosureDebugErrors createScanner() {
		return new InformationDisclosureDebugErrors();
	}
	
	@Test
	public void alertsIfDebugErrorsDisclosed() throws HttpMalformedHeaderException {
		String[] data = new String[] {
				"Internal Server Error",
				"There seems to have been a problem with the",
				"This error page might contain sensitive information because ASP.NET",
				"PHP Error"
		};
		
		for (int i = 0; i < data.length; i++) {
			String debugError = data[i];
			
			HttpMessage msg = new HttpMessage();
			msg.setRequestHeader("GET " + URI + " HTTP/1.1");
	        
	        msg.setResponseBody("<html>" + debugError + "</html>");
	        msg.setResponseHeader(
	                "HTTP/1.1 200 OK\r\n" +
	                "Server: Apache-Coyote/1.1\r\n" +
	                "Content-Type: text/html;charset=ISO-8859-1\r\n" +
	                "Content-Length: " + msg.getResponseBody().length() + "\r\n");
	        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

	        assertThat(alertsRaised.size(), equalTo(i + 1));
	        assertThat(alertsRaised.get(i).getCweId(), equalTo(200));
	        assertThat(alertsRaised.get(i).getWascId(), equalTo(13));
	        assertThat(alertsRaised.get(i).getEvidence(), equalTo(debugError));	
		}
	}
	
	@Test
	public void passesIfNoDebugErrorsDisclosed() throws HttpMalformedHeaderException {
		String[] data = new String[] {
				"Error Management theory",
				"a subject can make two possible errors",
				"What to Do If You Get a 404",
				"500"
		};
		
		for (int i = 0; i < data.length; i++) {
			String debugError = data[i];
			
			HttpMessage msg = new HttpMessage();
			msg.setRequestHeader("GET " + URI + " HTTP/1.1");
	        
	        msg.setResponseBody("<html>" + debugError + "</html>");
	        msg.setResponseHeader(
	                "HTTP/1.1 200 OK\r\n" +
	                "Server: Apache-Coyote/1.1\r\n" +
	                "Content-Type: text/html;charset=ISO-8859-1\r\n" +
	                "Content-Length: " + msg.getResponseBody().length() + "\r\n");
	        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

	        assertThat(alertsRaised.size(), equalTo(0));
		}		
	}
}
