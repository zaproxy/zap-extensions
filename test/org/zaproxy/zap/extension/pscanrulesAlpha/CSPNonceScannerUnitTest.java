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

import org.junit.Test;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * @author Greg Guthe (@g-k)
 */
public class CSPNonceScannerUnitTest extends PassiveScannerTest {

	@Override
	protected PluginPassiveScanner createScanner() {
		return new CSPNonceScanner();
	}

	@Test
	public void shouldNotRaiseAlertForScanHttpRequestSend() throws Exception {
	    // the method should do nothing (test just for code coverage)
	    rule.scanHttpRequestSend(null, -1);

	    // Then
	    assertThat(alertsRaised.size(), is(0));
	}

	@Test
	public void shouldNotRaiseAlertIfNoCSP() throws Exception {
		// Given
		HttpMessage msg = new HttpMessage();
		msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
		msg.setResponseHeader("HTTP/1.1 200 OK\r\n");

		// When
		rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

		// Then
		assertThat(alertsRaised.size(), is(0));
	}

	@Test
	public void shouldNotRaiseAlertIfCSPHeaderWithoutNonceSrc() throws Exception {
		// Given
		HttpMessage msg = new HttpMessage();
		msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
		msg.setResponseHeader("HTTP/1.1 200 OK\r\n" +
				      "Content-Security-Policy: default-src: 'none'\r\n");

		// When
		rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

		// Then
		assertThat(alertsRaised.size(), is(0));
	}

	@Test
	public void shouldNotRaiseAlertIfCSPMetaWithoutNonceSrc() throws Exception {
		// Given
		HttpMessage msg = new HttpMessage();
		msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
		msg.setResponseHeader("HTTP/1.1 200 OK\r\n" +
				      "Content-Type: text/html\r\n");
		msg.setResponseBody("<head><meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'self'\"></head>");

		// When
		rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

		// Then
		assertThat(alertsRaised.size(), is(0));
	}

	@Test
	public void shouldRaiseInvalidNonceAlertIfCSPMetaWithInvalidNonce() throws Exception {
		// Given
		HttpMessage msg = new HttpMessage();
		msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
		msg.setResponseHeader("HTTP/1.1 200 OK\r\n" +
				      "Content-Type: text/html\r\n");
		msg.setResponseBody("<head><meta http-equiv=\"Content-Security-Policy\" content=\"script-src nonce-not!-a-nonce?\"></head>");

		// When
		rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

		// Then
		assertThat(alertsRaised.size(), is(1));
		assertThat(alertsRaised.get(0).getEvidence(), is("not!-a-nonce?"));
	}

	@Test
	public void shouldRaiseInvalidNonceAlertIfCSPHeadersWithInvalidNonces() throws Exception {
		// Given
		HttpMessage msg = new HttpMessage();
		msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
		msg.setResponseHeader("HTTP/1.1 200 OK\r\n" +
				      "Content-Security-Policy: script-src nonce-not!-a-nonce?\r\n" +
				      "Content-Security-Policy: script-src nonce-also-not!-a-nonce?\r\n");

		// When
		rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

		// Then
		assertThat(alertsRaised.size(), is(2));
		assertThat(alertsRaised.get(0).getEvidence(), is("not!-a-nonce?"));
		assertThat(alertsRaised.get(1).getEvidence(), is("also-not!-a-nonce?"));
	}

	@Test
	public void shouldRaiseNonceReuseAlert() throws Exception {
		// Given
		HttpMessage msg = new HttpMessage();
		msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
		msg.setResponseHeader("HTTP/1.1 200 OK\r\n" +
				      "Content-Security-Policy: script-src nonce-reused\r\n");

		HttpMessage msg2 = new HttpMessage();
		msg2.setRequestHeader("GET https://www.example.com/test/2 HTTP/1.1");
		msg2.setResponseHeader("HTTP/1.1 200 OK\r\n" +
				       "Content-Security-Policy: script-src nonce-reused\r\n");

		// When
		rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));
		rule.scanHttpResponseReceive(msg2, -1, this.createSource(msg2));

		// Then
		assertThat(alertsRaised.size(), is(1));
		assertThat(alertsRaised.get(0).getEvidence(), is("reused"));
	}
}
