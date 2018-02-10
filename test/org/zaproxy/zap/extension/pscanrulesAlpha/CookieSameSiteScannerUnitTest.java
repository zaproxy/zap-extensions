/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP development team
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

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;
import org.junit.Test;

import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class CookieSameSiteScannerUnitTest extends PassiveScannerTest {

	@Override
	protected PluginPassiveScanner createScanner() {
		return new CookieSameSiteScanner();
	}

    @Test
	public void noSameSiteAttribute () throws HttpMalformedHeaderException {
		
		HttpMessage msg = new HttpMessage();
		msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");

		msg.setResponseBody("<html></html>");
		msg.setResponseHeader(
				"HTTP/1.1 200 OK\r\n" +
				"Server: Apache-Coyote/1.1\r\n" +
				"Set-Cookie: test=123; Path=/; HttpOnly\r\n" +
				"Content-Type: text/html;charset=ISO-8859-1\r\n" +
				"Content-Length: " + msg.getResponseBody().length() + "\r\n");
		rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

		assertThat(alertsRaised.size(), equalTo(1));
		assertThat(alertsRaised.get(0).getParam(), equalTo("test"));
		assertThat(alertsRaised.get(0).getEvidence(), equalTo("Set-Cookie: test"));
	}
    
    @Test
	public void noCookie () throws HttpMalformedHeaderException {
		
		HttpMessage msg = new HttpMessage();
		msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
		
		msg.setResponseBody("<html></html>");
		msg.setResponseHeader(
				"HTTP/1.1 200 OK\r\n" +
				"Server: Apache-Coyote/1.1\r\n" +
				"Content-Type: text/html;charset=ISO-8859-1\r\n" +
				"Content-Length: " + msg.getResponseBody().length() + "\r\n");
		rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

		assertThat(alertsRaised.size(), equalTo(0));
    }
    
    @Test
	public void laxSameSiteAttribute () throws HttpMalformedHeaderException {
		
		HttpMessage msg = new HttpMessage();
		msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
		
		msg.setResponseBody("<html></html>");
		msg.setResponseHeader(
				"HTTP/1.1 200 OK\r\n" +
				"Server: Apache-Coyote/1.1\r\n" +
				"Set-Cookie: test=123; Path=/; SameSite=Lax; HttpOnly\r\n" +
				"Content-Type: text/html;charset=ISO-8859-1\r\n" +
				"Content-Length: " + msg.getResponseBody().length() + "\r\n");
		rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

		assertThat(alertsRaised.size(), equalTo(0));
	}
    
    @Test
	public void strictSameSiteAttribute () throws HttpMalformedHeaderException {
		
		HttpMessage msg = new HttpMessage();
		msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
		
		msg.setResponseBody("<html></html>");
		msg.setResponseHeader(
				"HTTP/1.1 200 OK\r\n" +
				"Server: Apache-Coyote/1.1\r\n" +
				"Set-Cookie: test=123; Path=/; SameSite=strICt; HttpOnly\r\n" +
				"Content-Type: text/html;charset=ISO-8859-1\r\n" +
				"Content-Length: " + msg.getResponseBody().length() + "\r\n");
		rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

		assertThat(alertsRaised.size(), equalTo(0));
	}
    
    @Test
	public void secondCookieNoSameSiteAttribute () throws HttpMalformedHeaderException {
		
		HttpMessage msg = new HttpMessage();
		msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
		
		msg.setResponseBody("<html></html>");
		msg.setResponseHeader(
				"HTTP/1.1 200 OK\r\n" +
				"Server: Apache-Coyote/1.1\r\n" +
				"Set-Cookie: hasatt=test123; Path=/; SameSite=lax; HttpOnly\r\n" +
				"Set-Cookie: test=123; Path=/; HttpOnly\r\n" +
				"Content-Type: text/html;charset=ISO-8859-1\r\n" +
				"Content-Length: " + msg.getResponseBody().length() + "\r\n");
		rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

		assertThat(alertsRaised.size(), equalTo(1));
		assertThat(alertsRaised.get(0).getParam(), equalTo("test"));
		assertThat(alertsRaised.get(0).getEvidence(), equalTo("Set-Cookie: test"));
	}
    
    @Test
	public void badValSameSiteAttribute () throws HttpMalformedHeaderException {
		
		HttpMessage msg = new HttpMessage();
		msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
		
		msg.setResponseBody("<html></html>");
		msg.setResponseHeader(
				"HTTP/1.1 200 OK\r\n" +
				"Server: Apache-Coyote/1.1\r\n" +
				"Set-Cookie: test=123; Path=/; SameSite=badVal; HttpOnly\r\n" +
				"Content-Type: text/html;charset=ISO-8859-1\r\n" +
				"Content-Length: " + msg.getResponseBody().length() + "\r\n");
		rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

		assertThat(alertsRaised.size(), equalTo(1));
		assertThat(alertsRaised.get(0).getParam(), equalTo("test"));
		assertThat(alertsRaised.get(0).getEvidence(), equalTo("Set-Cookie: test"));
	}
    
    @Test
	public void noValSameSiteAttribute () throws HttpMalformedHeaderException {
		
		HttpMessage msg = new HttpMessage();
		msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
		
		msg.setResponseBody("<html></html>");
		msg.setResponseHeader(
				"HTTP/1.1 200 OK\r\n" +
				"Server: Apache-Coyote/1.1\r\n" +
				"Set-Cookie: test=123; Path=/; SameSite; HttpOnly\r\n" +
				"Content-Type: text/html;charset=ISO-8859-1\r\n" +
				"Content-Length: " + msg.getResponseBody().length() + "\r\n");
		rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

		assertThat(alertsRaised.size(), equalTo(1));
		assertThat(alertsRaised.get(0).getParam(), equalTo("test"));
		assertThat(alertsRaised.get(0).getEvidence(), equalTo("Set-Cookie: test"));
	}
}
