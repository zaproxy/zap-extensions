/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrulesBeta;

import static org.junit.Assert.assertEquals;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.Before;
import org.junit.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;

public class UsernameIdorScannerUnitTest extends PassiveScannerTest<UsernameIdorScanner> {

	private HttpMessage msg;

	// Hashes in lower case for "guest" without quotes
	private static final String GUEST_MD5 = "084e0343a0486ff05530df6c705c8bb4";
	private static final String GUEST_SHA1 = "84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec";

	@Before
	public void before() throws URIException {

		rule.setUsers("guest");

		HttpRequestHeader requestHeader = new HttpRequestHeader();
		requestHeader.setURI(new URI("http://example.com", false));

		msg = new HttpMessage();
		msg.setRequestHeader(requestHeader);
	}

	@Override
	protected UsernameIdorScanner createScanner() {
		return new UsernameIdorScanner();
	}

	@Test
	public void shouldNotRaiseAlertIfResponseHasNoRelevantContent() {
		// Given
		msg.setResponseBody("Some text <h1>Some Title Element</h1>");
		// When
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));
		// Then
		assertEquals(alertsRaised.size(), 0);
	}

	@Test
	public void shouldNotRaiseAlertIfResponseContainsIrrelevantHash() {
		// Given - "Guest" with a leading cap
		msg.setResponseBody("Some text <h1>Some Title Element</h1><i>adb831a7fdd83dd1e2a309ce7591dff8</i>");
		// When
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));
		// Then
		assertEquals(alertsRaised.size(), 0);
	}

	@Test
	public void shouldRaiseAlertIfResponseContainsRelevantMd5Hash() {
		// Given - Mixed case hash
		msg.setResponseBody("Some text <h1>Some Title Element</h1><i>084E0343A0486fF05530DF6C705C8Bb4</i>");
		// When
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));
		// Then
		assertEquals(alertsRaised.size(), 1);
		assertEquals(alertsRaised.get(0).getEvidence(), "084E0343A0486fF05530DF6C705C8Bb4");
	}

	@Test
	public void shouldRaiseAlertIfResponseContainsRelevantSha1Hash() {
		// Given
		msg.setResponseBody(
				"Some text <h1>Some Title Element</h1><b>84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec</b>");
		// When
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));
		// Then
		assertEquals(alertsRaised.size(), 1);
		assertEquals(alertsRaised.get(0).getEvidence(), GUEST_SHA1);
	}

	@Test
	public void shouldRaiseMultipleAlertsIfResponseContainsMultipleRelevantHashes() {
		// Given
		msg.setResponseBody("Some text <h1>Some Title Element</h1><b>" + GUEST_MD5 + "</b>"
				+ "<b>adb831a7fdd83dd1e2a309ce7591dff8</b>" + "<br>" + GUEST_SHA1 + "</b>");
		// When
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));
		// Then
		assertEquals(alertsRaised.size(), 2);
		assertEquals(alertsRaised.get(0).getEvidence(), GUEST_SHA1);
		assertEquals(alertsRaised.get(1).getEvidence(), GUEST_MD5);
	}
	
	@Test
	public void shouldRaiseAlertIfResponseContainsRelevantHashInHeader() {
		// Given
		msg.getResponseHeader().setHeader("X-Test-Thing", GUEST_MD5);
		msg.setResponseBody("Some text <h1>Some Title Element</h1><p>Lorem ipsum dolor "
				+ "sit amet, consectetur adipiscing elit. Nunc tempor mi et "
				+ "pulvinar convallis. Maecenas laoreet fermentum tempor. " + "Nulla et.</p>");
		// When
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));
		// Then
		assertEquals(alertsRaised.size(), 1);
		assertEquals(alertsRaised.get(0).getEvidence(), GUEST_MD5);
	}

}
