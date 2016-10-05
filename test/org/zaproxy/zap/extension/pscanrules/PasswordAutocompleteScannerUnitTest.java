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
package org.zaproxy.zap.extension.pscanrules;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;

import org.junit.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

public class PasswordAutocompleteScannerUnitTest extends PassiveScannerTest {
	private static final String URI = "https://www.example.com/";

	@Override
	protected PasswordAutocompleteScanner createScanner() {
		return new PasswordAutocompleteScanner();
	}

	@Test
	public void shouldPassIfNoHtml() throws HttpMalformedHeaderException {
		HttpMessage msg = createHttpMessage("Lorem Ipsum");
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));

		assertThat(alertsRaised.size(), equalTo(0));
	}

	@Test
	public void shouldPassIfNoForm() throws HttpMalformedHeaderException {
		HttpMessage msg = createHttpMessage("<html><body></body></html>");
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));

		assertThat(alertsRaised.size(), equalTo(0));
	}

	@Test
	public void shouldPassIfEmptyForm() throws HttpMalformedHeaderException {
		HttpMessage msg = createHttpMessage("<html><form></form></html>");
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));

		assertThat(alertsRaised.size(), equalTo(0));
	}

	@Test
	public void shouldPassIfAutocompleteInEmptyForm() throws HttpMalformedHeaderException {
		HttpMessage msg = createHttpMessage("<form autocomplete='off'></form>");
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));

		assertThat(alertsRaised.size(), equalTo(0));
	}

	@Test
	public void shouldPassIfNoPasswordField() throws HttpMalformedHeaderException {
		String body =
				"<form>" +
				"<input name='password' id='password'>" +
				"</form>";
		HttpMessage msg = createHttpMessage(body);
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));

		assertThat(alertsRaised.size(), equalTo(0));
	}

	@Test
	public void shouldPassIfAutocompleteInPasswordField() throws HttpMalformedHeaderException {
		String body =
				"<form>" +
				"<input name='pw' type='password' autocomplete='off'>" +
				"</form>";
		HttpMessage msg = createHttpMessage(body);
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));

		assertThat(alertsRaised.size(), equalTo(0));
	}

	@Test
	public void shouldPassIfTypoInAutocompleteOfFormWithNoPasswordField() throws HttpMalformedHeaderException {
		String body =
				"<form autocomplete='pff'>" +
				"<input name='password' id='a' type='text'>" +
				"<input name='b' id='password'>" +
				"</form>";
		HttpMessage msg = createHttpMessage(body);
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));

		assertThat(alertsRaised.size(), equalTo(0));
	}

	@Test
	public void shouldPassIfNoNameOrIdInPasswordField() throws HttpMalformedHeaderException {
		String body =
				"<form>" +
				"<input type='password' autocomplete='off'>" +
				"</form>";
		HttpMessage msg = createHttpMessage(body);
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));

		assertThat(alertsRaised.size(), equalTo(0));
	}

	@Test
	public void shouldRaiseAlertIfTypoInAutocompleteOfFormTag() throws HttpMalformedHeaderException {
		String body =
				"<form autocomplete='pff'>" +
				"<input name='pw' type='password'>" +
				"</form>";
		HttpMessage msg = createHttpMessage(body);
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));

		assertThat(alertsRaised.size(), equalTo(1));
		assertThat(alertsRaised.get(0).getParam(), equalTo("pw"));
		assertThat(alertsRaised.get(0).getEvidence(), equalTo("<input name='pw' type='password'>"));
	}

	@Test
	public void shouldRaiseAlertIfTypoInAutocompleteOfPasswordField() throws HttpMalformedHeaderException {
		String body =
				"<form>" +
				"<input name='pw' type='password' autocomplete='opf'>" +
				"</form>";
		HttpMessage msg = createHttpMessage(body);
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));

		assertThat(alertsRaised.size(), equalTo(1));
		assertThat(alertsRaised.get(0).getParam(), equalTo("pw"));
		assertThat(alertsRaised.get(0).getEvidence(), equalTo("<input name='pw' type='password' autocomplete='opf'>"));
	}

	@Test
	public void shouldRaiseAlertIfPasswordFieldAndFormHasNoAutocomplete() throws HttpMalformedHeaderException {
		String body =
				"<form>" +
				"<input name='pw' id='aId' type='password'>" +
				"</form>";
		HttpMessage msg = createHttpMessage(body);
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));

		assertThat(alertsRaised.size(), equalTo(1));
		assertThat(alertsRaised.get(0).getParam(), equalTo("aId"));
		assertThat(alertsRaised.get(0).getEvidence(), equalTo("<input name='pw' id='aId' type='password'>"));
	}

	@Test
	public void shouldRaiseAlertIfAutocompleteIsInWrongTag() throws HttpMalformedHeaderException {
		String body =
				"<form>" +
				"<input name='usr' type='text' autocomplete='off'>" +
				"<input name='pw' type='password'>" +
				"</form>";
		HttpMessage msg = createHttpMessage(body);
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));

		assertThat(alertsRaised.size(), equalTo(1));
		assertThat(alertsRaised.get(0).getParam(), equalTo("pw"));
		assertThat(alertsRaised.get(0).getEvidence(), equalTo("<input name='pw' type='password'>"));
	}

	@Test
	public void shouldRaiseAlertIfOneAutocompleteOfFormTagInTwoForms() throws HttpMalformedHeaderException {
		String body =
				"<form action='login1' autocomplete='off'>" +
				"<input name='pw1' id='aId1' type='password'>" +
				"</form>" +
				"<form action='login2'>" +
				"<input name='pw2' id='aId2' type='password'>" +
				"</form>";
		HttpMessage msg = createHttpMessage(body);
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));

		assertThat(alertsRaised.size(), equalTo(1));
		assertThat(alertsRaised.get(0).getParam(), equalTo("aId2"));
		assertThat(alertsRaised.get(0).getEvidence(), equalTo("<input name='pw2' id='aId2' type='password'>"));
	}

	@Test
	public void shouldRaiseAlertIfNoAutocompleteInTwoForms() throws HttpMalformedHeaderException {
		String body =
				"<form action='login1'>" +
				"<input name='pw1' type='password'>" +
				"</form>" +
				"<form action='login2'>" +
				"<input name='pw2' type='password'>" +
				"</form>";
		HttpMessage msg = createHttpMessage(body);
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));

		String [][] checkValues = new String [][] {
				{"pw1", "<input name='pw1' type='password'>"},
				{"pw2", "<input name='pw2' type='password'>"}
		};
		assertThat(alertsRaised.size(), equalTo(2));
		for (int i = 0; i < alertsRaised.size(); i++) {
			assertThat(alertsRaised.get(i).getParam(), equalTo(checkValues[i][0]));
			assertThat(alertsRaised.get(i).getEvidence(), equalTo(checkValues[i][1]));
			validateAlert(alertsRaised.get(i));
		}
	}

	@Test
	public void shouldRaiseAlertIfOneAutocompleteOfPasswordFieldInTwoForms() throws HttpMalformedHeaderException {
		String body =
				"<form action='login1'>" +
				"<input name='pw1' type='password' autocomplete='off'>" +
				"</form>" +
				"<form action='login2'>" +
				"<input name='pw2' type='password'>" +
				"</form>";
		HttpMessage msg = createHttpMessage(body);
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));

		assertThat(alertsRaised.size(), equalTo(1));
		assertThat(alertsRaised.get(0).getParam(), equalTo("pw2"));
		assertThat(alertsRaised.get(0).getEvidence(), equalTo("<input name='pw2' type='password'>"));
	}


	@Test
	public void TestOfScanHttpRequestSend() throws HttpMalformedHeaderException {
		// the method should do nothing (test just for maybe later code coverage)
		rule.scanHttpRequestSend(null, -1);
		assertThat(alertsRaised.size(), equalTo(0));
	}

	private static void validateAlert(Alert alert) {
		assertThat(alert.getPluginId(), equalTo(10012));
		assertThat(alert.getRisk(), equalTo(Alert.RISK_LOW));
		assertThat(alert.getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
		assertThat(alert.getUri(), equalTo(URI));
	}	

	private static HttpMessage createHttpMessage(String body) throws HttpMalformedHeaderException {
		HttpMessage msg = new HttpMessage();
		msg.setRequestHeader("GET " + URI + " HTTP/1.1");
		msg.setResponseHeader("HTTP/1.1 200 OK\r\n");
		msg.setResponseBody(body);
		return msg;
	}

}
