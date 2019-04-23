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
package org.zaproxy.zap.extension.pscanrules;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.util.Arrays;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.Before;
import org.junit.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.encoder.Base64;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;

public class ViewStateScannerUnitTest extends PassiveScannerTest<ViewstateScanner> {
	
	private HttpMessage msg;
	private HttpRequestHeader header;

	@Before
	public void before() throws URIException {
		msg = new HttpMessage();
		header = new HttpRequestHeader();
		
		msg.setRequestHeader(header);
		header.setURI(new URI("http://example.com", true));
	}
	
	@Override
	protected ViewstateScanner createScanner() {
		return new ViewstateScanner();
	}
	
	@Test
	public void shouldNotRaiseAlertAsThereIsNoContent() {
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));
		
		assertThat(alertsRaised.size(), equalTo(0));
	}
	
	@Test
	public void shouldNotRaiseAlertAsThereIsNoValidViewState() {
		msg.setResponseBody("<input name=\"__specialstate\">");
		
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));
		
		assertThat(alertsRaised.size(), equalTo(0));
	} 
	
	@Test
	public void shouldNotRaiseAlertAsThereIsAnUnknowVersionOfASP() {
		msg.setResponseBody("<input name=\"__specialstate\" value=\"bm90dmFsaWQ=\">");
		
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));

		assertThat(alertsRaised.size(), equalTo(0));
	}
	
	@Test
	public void shouldRaiseAlertAsThereIsNoValidMACUnsure() {
		msg.setResponseBody("<input name=\"__VIEWSTATE\" value=\"/wEPDWUKMTkwNjc4NTIwMWRkaKrolbpTKYmPUNsab597kh8iOBU=\">");
		
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));

		assertThat(alertsRaised.size(), equalTo(1));
		assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
		assertThat(alertsRaised.get(0).getName(), equalTo("Viewstate without MAC Signature (Unsure)"));
		assertThat(alertsRaised.get(0).getWascId(), equalTo(14));
		assertThat(alertsRaised.get(0).getCweId(), equalTo(642));
		assertSame(msg, alertsRaised.get(0).getMessage());
	}

	@Test
	public void shouldRaiseAlertAsThereIsNoValidMACSure() {
		msg.setResponseBody("<input name=\"__VIEWSTATE\" value=\"/wEPDWUKMTkwNjc4NTIwwEPDWUKMTkwNjc4NTIwMWRkaMWRka\">");
		
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));

		assertThat(alertsRaised.size(), equalTo(1));
		assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
		assertThat(alertsRaised.get(0).getName(), equalTo("Viewstate without MAC Signature (Sure)"));
		assertThat(alertsRaised.get(0).getWascId(), equalTo(14));
		assertThat(alertsRaised.get(0).getCweId(), equalTo(642));
		assertSame(msg, alertsRaised.get(0).getMessage());
	}
	
	@Test
	public void shouldRaiseAlertForOldASPVersion() {
		msg.setResponseBody("<input name=\"__VIEWSTATE\" value=\"dDPDWUKMTkwNjc4NTIwMWRkaKrolbpTKYmPUNsab597kh8iOBU=\">");
		
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));
		
		assertThat("There should be two alerts raised.", alertsRaised.size(), equalTo(2));
		assertThat(alertsRaised.get(1).getRisk(), equalTo(Alert.RISK_LOW));
		assertThat(alertsRaised.get(1).getName(), equalTo("Old Asp.Net Version in Use"));
		assertThat(alertsRaised.get(1).getWascId(), equalTo(14));
		assertThat(alertsRaised.get(1).getCweId(), equalTo(16));
		assertThat(alertsRaised.get(1).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
		assertSame(msg, alertsRaised.get(1).getMessage());
	}
	
	@Test
	public void shouldNotRaiseAlertAsTheParametersDoNotHaveEmailsOrIps() {
		msg.setResponseBody("<input name=\"__VIEWSTATE\" value=\"/wEPDwUJODczNjQ5OTk0D2QWAgIDD2QWAgIFDw8WAh4EVGV4dAUWSSBMb3ZlIERvdG5ldEN1cnJ5LmNvbWRkZMHbBY9JqBTvB5/6kXnY15AUSAwa\">");
		
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));

		assertThat(alertsRaised.size(), equalTo(0));
	}	
	
	@Test
	public void shouldRaiseAlertBecauseTheParametersDoesHaveEmail() {
		String encodedViewstate = getViewstateWithText("test@test.com");
		msg.setResponseBody("<input name=\"__VIEWSTATE\" value=\"" + encodedViewstate +  "\">");
		
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));

		assertThat(alertsRaised.size(), equalTo(1));
		assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_MEDIUM));
		assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
		assertThat(alertsRaised.get(0).getName(), equalTo("Emails Found in the Viewstate"));
		assertThat(alertsRaised.get(0).getOtherInfo(), equalTo("[Itest@test.com]"));
		assertThat(alertsRaised.get(0).getWascId(), equalTo(14));
		assertThat(alertsRaised.get(0).getCweId(), equalTo(16));
		assertSame(msg, alertsRaised.get(0).getMessage());
	}	
	
	@Test
	public void shouldRaiseAlertBecauseTheParametersDoesHaveIP() {
		String encodedViewstate = getViewstateWithText("127.0.0.1");
		msg.setResponseBody("<input name=\"__VIEWSTATE\" value=\"" + encodedViewstate +  "\">");
		
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));

		assertThat(alertsRaised.size(), equalTo(1));
		assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_MEDIUM));
		assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
		assertThat(alertsRaised.get(0).getName(), equalTo("Potential IP Addresses Found in the Viewstate"));
		assertThat(alertsRaised.get(0).getDescription(), equalTo("The following potential IP addresses were found being serialized in the viewstate field:"));
		assertThat(alertsRaised.get(0).getOtherInfo(), equalTo("[127.0.0.1]"));
		assertThat(alertsRaised.get(0).getWascId(), equalTo(14));
		assertThat(alertsRaised.get(0).getCweId(), equalTo(16));
		assertSame(msg, alertsRaised.get(0).getMessage());
	}
	
	@Test
	public void shouldRaiseAlertAsViewstateIsSplit() {
		msg.setResponseBody(	"<input type=\"hidden\" name=\"__VIEWSTATEFIELDCOUNT\" id=\"__VIEWSTATEFIELDCOUNT\" value=\"3\" />"
					+ "<input type=\"hidden\" name=\"__VIEWSTATE\" id=\"__VIEWSTATE\" value=\"/wEPDwUKLTk2Njk3OTQxNg9kFgICAw9kFgICCQ88\" />" 
					+ "<input type=\"hidden\" name=\"__VIEWSTATE1\" id=\"__VIEWSTATE1\" value=\"KwANAGQYAQUJR3JpZFZpZXcxD2dk4sjERFfnDXV/\" />"
					+ "<input type=\"hidden\" name=\"__VIEWSTATE2\" id=\"__VIEWSTATE2\" value=\"hMFGAL10HQUnZbk=\" />");
		
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));

		assertThat(alertsRaised.size(), equalTo(2));
		assertThat(alertsRaised.get(1).getRisk(), equalTo(Alert.RISK_INFO));
		assertThat(alertsRaised.get(1).getName(), equalTo("Split Viewstate in Use"));
		assertThat(alertsRaised.get(1).getWascId(), equalTo(14));
		assertThat(alertsRaised.get(1).getCweId(), equalTo(16));
		assertSame(msg, alertsRaised.get(0).getMessage());
	}	
		
	/**
	 * Helper function for injecting a piece of text into a valid base64 encoded ASP Viewstate.
	 * @param inject the string to inject
	 * @return a base64 encoded string with the inject value injected at byte 40.
	 */
	private String getViewstateWithText(String inject) {
		String base = "/wEPDwUJODczNjQ5OTk0D2QWAgIDD2QWAgIFDw8WAh4EVGV4dAUWSSBMb3ZlIERvdG5ldEN1cnJ5LmNvbWRkZMHbBY9JqBTvB5/6kXnY15AUSAwa";
		byte[] decoded;
		try {
			decoded = Base64.decode(base);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		
		byte[] part1 = Arrays.copyOf(decoded, 40);
		byte[] part2 = Arrays.copyOfRange(decoded, 40, decoded.length);
		byte[] injectBytes = inject.getBytes();
		
		
		byte[] result = new byte[part1.length + injectBytes.length + part2.length];
		
		System.arraycopy(part1, 0, result, 0, part1.length);
		System.arraycopy(injectBytes, 0, result, part1.length, injectBytes.length);
		System.arraycopy(part2, 0, result, part1.length + injectBytes.length, part2.length);		

		String reEncoded = Base64.encodeBytes(result);
		return reEncoded;
	}
}