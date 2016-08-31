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
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

public class PasswordAutocompleteScannerUnitTest extends PassiveScannerTest {

	@Override
	protected PasswordAutocompleteScanner createScanner() {
		return new PasswordAutocompleteScanner();
	}

	private HttpMessage createHttpMessage(String body) throws HttpMalformedHeaderException {
		HttpMessage msg = new HttpMessage();
		msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
		msg.setResponseHeader("HTTP/1.1 200 OK\r\n");
		msg.setResponseBody(body);
		return msg;
	}

	@Test
	public void shouldPassIfThereIsNoFormAtAll() throws HttpMalformedHeaderException {
		HttpMessage msg = createHttpMessage("<html><body></body></html>");
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));

		assertThat(alertsRaised.size(), equalTo(0));
	}

	@Test
	public void shouldPassWithAutocompleteInFormTag() throws HttpMalformedHeaderException {
		String body = "<html>" +
				"<form method='POST' action='dologin' autocomplete='off'>" +
				"Name: <input name='usr' value='' type='text'>" +
				"Pass: <input name='pw' type='password'>" +
				"<input type='submit' value='Login'/>" +
				"</form></html>";
		HttpMessage msg = createHttpMessage(body);
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));

		assertThat(alertsRaised.size(), equalTo(0));
	}

	@Test
	public void shouldPassWithAutocompleteInPasswordField() throws HttpMalformedHeaderException {
		String body = "<html>" +
				"<form method='POST' action='dologin'>" +
				"Name: <input name='usr' value='' type='text'>" +
				"Pass: <input name='pw' type='password' autocomplete='off'>" +
				"</form></html>";
		HttpMessage msg = createHttpMessage(body);
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));

		assertThat(alertsRaised.size(), equalTo(0));
	}

	@Test
	public void shouldRaiseAlertIfThereIsATypoInTheAutocompleteAttributeInTheFormTag() throws HttpMalformedHeaderException {
		String body = "<html>" +
				"<form method='POST' action='dologin' autocomplete='pff'>" +
				"Name: <input name='usr' value='' type='text'>" +
				"Pass: <input name='pw' type='password'>" +
				"<input type='submit' value='Login'/>" +
				"</form></html>";
		HttpMessage msg = createHttpMessage(body);
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));

		assertThat(alertsRaised.size(), equalTo(1));
		assertThat(alertsRaised.get(0).getParam(), equalTo("pw"));
		assertThat(alertsRaised.get(0).getEvidence(), equalTo("<input name='pw' type='password'>"));
	}

	@Test
	public void shouldRaiseAlertIfThereIsATypoInTheAutocompleteAttributeInThePasswordField() throws HttpMalformedHeaderException {
		String body = "<html>" +
				"<form method='POST' action='dologin'>" +
				"Name: <input name='usr' value='' type='text'>" +
				"Pass: <input name='pw' type='password' autocomplete='pff'>" +
				"<input type='submit' value='Login'/>" +
				"</form></html>";
		HttpMessage msg = createHttpMessage(body);
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));

		assertThat(alertsRaised.size(), equalTo(1));
		assertThat(alertsRaised.get(0).getParam(), equalTo("pw"));
		assertThat(alertsRaised.get(0).getEvidence(), equalTo("<input name='pw' type='password' autocomplete='pff'>"));
	}

	@Test
	public void shouldRaiseAlertIfThereIsNoNameAndNoIdInThePasswordField() throws HttpMalformedHeaderException {
		String body = "<html>" +
				"<form method='POST' action='dologin'>" +
				"Name: <input name='usr' value='' type='text'>" +
				"Pass: <input type='password' autocomplete='off'>" +
				"<input type='submit' value='Login'/>" +
				"</form></html>";
		HttpMessage msg = createHttpMessage(body);
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));

		assertThat(alertsRaised.size(), equalTo(0));
	}

	@Test
	public void shouldRaiseAlertIfThereIsNoTypeInThePasswordField() throws HttpMalformedHeaderException {
		String body = "<html>" +
				"<form method='POST' action='dologin'>" +
				"Name: <input name='usr' value='' type='text'>" +
				"Pass: <input name='pw' autocomplete='off'>" +
				"<input type='submit' value='Login'/>" +
				"</form></html>";
		HttpMessage msg = createHttpMessage(body);
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));

		assertThat(alertsRaised.size(), equalTo(0));
	}

	@Test
	public void shouldRaiseAlertIfPasswordFieldAndFormHasNoAutocomplete() throws HttpMalformedHeaderException {
		String body = "<html>" +
				"<form method='POST' action='dologin'>" +
				"Name: <input name='usr' value='' type='text'>" +
				"Pass: <input name='pw' id='aId' type='password'>" +
				"</form></html>";
		HttpMessage msg = createHttpMessage(body);
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));

		assertThat(alertsRaised.size(), equalTo(1));
		assertThat(alertsRaised.get(0).getParam(), equalTo("aId"));
		assertThat(alertsRaised.get(0).getEvidence(), equalTo("<input name='pw' id='aId' type='password'>"));
	}

	@Test
	public void shouldRaiseAlertIfAutocompleteIsInWrongTag() throws HttpMalformedHeaderException {
		String body = "<html>" +
				"<form method='POST' action='dologin'>" +
				"Name: <input name='usr' value='' type='text' autocomplete='off'>" +
				"Pass: <input name='pw' type='password'>" +
				"</form></html>";
		HttpMessage msg = createHttpMessage(body);
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));

		assertThat(alertsRaised.size(), equalTo(1));
		assertThat(alertsRaised.get(0).getParam(), equalTo("pw"));
		assertThat(alertsRaised.get(0).getEvidence(), equalTo("<input name='pw' type='password'>"));
	}

	@Test
	public void shouldRaiseAlertIfThereIsInTwoFormsOnlyOneAutocompleteInTheFormTag() throws HttpMalformedHeaderException {
		String body = "<html>" +
				"<form method='POST' action='login1' autocomplete='off'>" +
				"Name: <input name='usr1' value='' type='text'>" +
				"Pass: <input name='pw1' id='aId1' type='password'>" +
				"<input type='submit' value='go1'/>" +
				"</form>" +
				"<form method='POST' action='login2'>" +
				"Name: <input name='usr2' value='' type='text'>" +
				"Pass: <input name='pw2' id='aId2' type='password'>" +
				"<input type='submit' value='go2'/>" +
				"</form></html>";
		HttpMessage msg = createHttpMessage(body);
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));

		assertThat(alertsRaised.size(), equalTo(1));
		assertThat(alertsRaised.get(0).getParam(), equalTo("aId2"));
		assertThat(alertsRaised.get(0).getEvidence(), equalTo("<input name='pw2' id='aId2' type='password'>"));
	}

	@Test
	public void shouldRaiseAlertIfThereIsInTwoFormsOnlyOneAutocompleteInThePasswordField() throws HttpMalformedHeaderException {
		String body = "<html>" +
				"<form method='POST' action='login1'>" +
				"Name: <input name='usr1' value='' type='text'>" +
				"Pass: <input name='pw1' type='password' autocomplete='off'>" +
				"<input type='submit' value='go1'/>" +
				"</form>" +
				"<form method='POST' action='login2'>" +
				"Name: <input name='usr2' value='' type='text'>" +
				"Pass: <input name='pw2' type='password'>" +
				"<input type='submit' value='go2'/>" +
				"</form></html>";
		HttpMessage msg = createHttpMessage(body);
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));

		assertThat(alertsRaised.size(), equalTo(1));
		assertThat(alertsRaised.get(0).getParam(), equalTo("pw2"));
		assertThat(alertsRaised.get(0).getEvidence(), equalTo("<input name='pw2' type='password'>"));
	}

	@Test
	public void shouldRaiseAlertIfThereIsInTwoFormsNoAutocompleteAtAll() throws HttpMalformedHeaderException {
		String body = "<html>" +
				"<form method='POST' action='login1'>" +
				"Name: <input name='usr1' value='' type='text'>" +
				"Pass: <input name='pw1' type='password'>" +
				"<input type='submit' value='go1'/>" +
				"</form>" +
				"<form method='POST' action='login2'>" +
				"Name: <input name='usr2' value='' type='text'>" +
				"Pass: <input name='pw2' type='password'>" +
				"<input type='submit' value='go2'/>" +
				"</form></html>";
		HttpMessage msg = createHttpMessage(body);
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));

		assertThat(alertsRaised.size(), equalTo(2));
		assertThat(alertsRaised.get(0).getParam(), equalTo("pw1"));
		assertThat(alertsRaised.get(0).getEvidence(), equalTo("<input name='pw1' type='password'>"));
		assertThat(alertsRaised.get(1).getParam(), equalTo("pw2"));
		assertThat(alertsRaised.get(1).getEvidence(), equalTo("<input name='pw2' type='password'>"));
	}

}
