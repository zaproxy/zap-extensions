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
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class TestInfoPrivateAddressDisclosureUnitTest extends PassiveScannerTest {

	@Override
	protected PluginPassiveScanner createScanner() {
		return new TestInfoPrivateAddressDisclosure();
	}

	private HttpMessage createHttpMessage(String body) throws HttpMalformedHeaderException {
		HttpMessage msg = new HttpMessage();
		msg.setRequestHeader("GET https://www.example.com/ HTTP/1.1");
		msg.setResponseHeader("HTTP/1.1 200 OK\r\n");
		msg.setResponseBody(body);
		return msg;
	}


	@Test
	public void alertsIfPrivateIp() throws HttpMalformedHeaderException {
		String[][] data = new String[][] {
				// IPs defined in RFC 1918
				{ "10.0.0.0",           "10.0.0.0" },
				{ "10.10.10.10",        "10.10.10.10" },
				{ "10.255.255.255",     "10.255.255.255" },
				{ "172.16.0.0",         "172.16.0.0" },
				{ "172.25.16.32",       "172.25.16.32" },
				{ "172.31.255.255",     "172.31.255.255" },
				{ "192.168.0.0",        "192.168.0.0" },
				{ "192.168.36.127",     "192.168.36.127" },
				{ "192.168.255.255",    "192.168.255.255" },
				// some OK stuff (?)
				{ "10.0.0.0:",          "10.0.0.0" },
				{ "10.0.0.0:6553",      "10.0.0.0:6553" },
				{ " 10.0.0.0 ",         "10.0.0.0" },
				{ "/10.0.0.0.",         "10.0.0.0" },
				{ ";10.0.0.0,",         "10.0.0.0" },
				{ "\n10.0.0.0\t",       "10.0.0.0" },
				{ "\n10.0.0.0\t",       "10.0.0.0" },
				// desired functionality?
				{ "10.0.0.0:bla",       "10.0.0.0:" },
				{ "15.10.0.0.0.12.27",  "10.0.0.0" },
				{ "255.10.0.0.0:6555",  "10.0.0.0:6555" },
				{ "100.10.0.0.0.10.12", "10.0.0.0" }, 
				{ "2050:10.0.0.0bla",   "10.0.0.0" },
				{ "205010.0.0.0bla",    "10.0.0.0" },
				{ "abcd10.0.0.0bla",    "10.0.0.0" },
				{ "abcd10.0.0.999",     "10.0.0.99" },
				{ "abcd10.0.0.9999999", "10.0.0.99" },
				{ "ip-10.0.0.0",        "10.0.0.0" }
		};
		for (int i = 0; i < data.length; i++) {
			String candidate = data[i][0];
			String evidence = data[i][1];
			HttpMessage msg = createHttpMessage(candidate);
			rule.scanHttpResponseReceive(msg, -1, createSource(msg));

			assertThat(alertsRaised.size(), equalTo(i + 1));
			assertThat(alertsRaised.get(i).getEvidence(), equalTo(evidence));
		}
	}

	@Test
	public void passesIfNonPrivateOrInvalidIp() throws HttpMalformedHeaderException {
		String[] candidates = new String[] {
				// define the "borders" of private IP ranges
				"9.255.255.255",
				"11.0.0.0",
				"172.15.255.255",
				"172.32.0.0",
				"192.167.255.255",
				"192.169.0.0",
				// somewhere outside & between the private ranges
				"8.8.8.8",
				"26.10.3.11",
				"84.168.27.12",
				"127.0.0.1",	// the original comment said: "IP's including localhost" should we add it?
				"186.27.16.2",
				"255.255.255.255",
				// some invalid ones
				"10",
				"10.0.0",
				"10.0.0:0",
				"10/0.0.0",
				"10.0\n0.0",
				"10.0.0 0",
				"10.0.0.a",
				"999.0.0.0", 
				"10.999.0.0",
				"10.0.756.0",
				// desired functionality?
//				"10.0.0.999", // would raise an alert, pls. find the others in privateIps()
		};
		for (String candidate : candidates) {
			HttpMessage msg = createHttpMessage(candidate);
			rule.scanHttpResponseReceive(msg, -1, createSource(msg));
		}
		assertThat(alertsRaised.size(), equalTo(0));
	}

	@Test
	public void alertsIfPrivIpAndAddsPortToEvidence() throws HttpMalformedHeaderException {
		String[] candidates = new String[] {
				// ranges like in regex 
				"10.0.0.0:0",     "10.0.0.0:9999",

				"10.0.0.0:65000", "10.0.0.0:65029",
				"10.0.0.0:65200", "10.0.0.0:65229",
				"10.0.0.0:65300", "10.0.0.0:65329",
				"10.0.0.0:65400", "10.0.0.0:65429",
				"10.0.0.0:65500", "10.0.0.0:65529",

				"10.0.0.0:60000", "10.0.0.0:64999",

				"10.0.0.0:65530", "10.0.0.0:65535",

				// values inside the ranges
				"10.0.0.0:0000",  "10.0.0.0:00000",
				"10.0.0.0:1",     "10.0.0.0:25",
				"10.0.0.0:128",   "10.0.0.0:443",
				"10.0.0.0:59999", "10.0.0.0:8080",

				"10.0.0.0:65012", "10.0.0.0:65023",
				"10.0.0.0:65209", "10.0.0.0:65218",
				"10.0.0.0:65313", "10.0.0.0:65327",
				"10.0.0.0:65402", "10.0.0.0:65419",
				"10.0.0.0:65516", "10.0.0.0:65525",

				"10.0.0.0:62512", "10.0.0.0:63256",

				"10.0.0.0:65532", "10.0.0.0:65534"
		};
		for (int i = 0; i < candidates.length; i++) {
			String candidate = candidates[i];
			HttpMessage msg = createHttpMessage(candidate);
			rule.scanHttpResponseReceive(msg, -1, createSource(msg));

			assertThat(alertsRaised.size(), equalTo(i + 1));
			assertThat(alertsRaised.get(i).getEvidence(), equalTo(candidate));
		}
	}

	@Test
	public void alertsIfPrivIpAndAddsCroppedNumberAsPortToEvidence() throws HttpMalformedHeaderException {
		String[][] data = new String[][] {
				// values outside (between) the small regex-ranges
				{ "10.0.0.0:65536",  "10.0.0.0:6553" },
				{ "10.0.0.0:65199",  "10.0.0.0:6519" },
				{ "10.0.0.0:65230",  "10.0.0.0:6523" },
				{ "10.0.0.0:65356",  "10.0.0.0:6535" },
				{ "10.0.0.0:65443",  "10.0.0.0:6544" },
				{ "10.0.0.0:65536",  "10.0.0.0:6553" },
				// the msg-body proceeds with digits
				{ "10.0.0.0:600000", "10.0.0.0:60000" },
				{ "10.0.0.0:649999", "10.0.0.0:64999" },
				{ "10.0.0.0:599999", "10.0.0.0:59999" },
				{ "10.0.0.0:650000", "10.0.0.0:65000" },
				{ "10.0.0.0:987654", "10.0.0.0:9876" },
				// some other stuff
				{ "10.0.0.0:64999A", "10.0.0.0:64999" },
				{ "10.0.0.0:649:30", "10.0.0.0:649" }
		};
		for (int i = 0; i < data.length; i++) {
			String candidate = data[i][0];
			String evidence = data[i][1];
			HttpMessage msg = createHttpMessage(candidate);
			rule.scanHttpResponseReceive(msg, -1, createSource(msg));

			assertThat(alertsRaised.size(), equalTo(i + 1));
			assertThat(alertsRaised.get(i).getEvidence(), equalTo(evidence));
		}
	}

	@Test
	public void alertsIfPrivateAwsHostname() throws HttpMalformedHeaderException {
		String[][] data = new String[][] {
			// Pattern of IPs defined in RFC 1918
			{ "ip-10-0-0-0",          "ip-10-0-0-0" },
			{ "ip-10-10-10-10",       "ip-10-10-10-10" },
			{ "ip-10-255-255-255",    "ip-10-255-255-255" },
			{ "ip-172-16-0-0",        "ip-172-16-0-0" },
			{ "ip-172-25-16-32",      "ip-172-25-16-32" },
			{ "ip-172-31-255-255",    "ip-172-31-255-255" },
			{ "ip-192-168-0-0",       "ip-192-168-0-0" },
			{ "ip-192-168-36-127",    "ip-192-168-36-127" },
			{ "ip-192-168-255-255",   "ip-192-168-255-255" },
			// other stuff
			{ "ip-10-0-0-0:",         "ip-10-0-0-0" },
			{ "ip-10-0-0-0:6553",     "ip-10-0-0-0:6553" },
			{ " ip-10-0-0-0 ",        "ip-10-0-0-0" },
			{ "/ip-10-0-0-0-",        "ip-10-0-0-0" },
			{ ";ip-10-0-0-0,",        "ip-10-0-0-0" },
			{ "\nip-10-0-0-0\t",      "ip-10-0-0-0" },

			{ "ip-10-0-0-0:bla",      "ip-10-0-0-0:" },
			{ "15-ip-10-0-0-0-12-27", "ip-10-0-0-0" },
			{ "255:ip-10-0-0-0:6555", "ip-10-0-0-0:6555" },
			{ "2050ip-10-0-0-0bla",   "ip-10-0-0-0" },
			{ "gossip-10-0-0-0bla",   "ip-10-0-0-0" },
			{ "ip-10-0-0-999",        "ip-10-0-0-99" },
			{ "ip-10-0-0-9999999",    "ip-10-0-0-99" },

			{ "ip-10.0.0.0",          "10.0.0.0" }
		};
		for (int i = 0; i < data.length; i++) {
			String candidate = data[i][0];
			String evidence = data[i][1];
			HttpMessage msg = createHttpMessage(candidate);
			rule.scanHttpResponseReceive(msg, -1, createSource(msg));
	
			assertThat(alertsRaised.size(), equalTo(i + 1));
			assertThat(alertsRaised.get(i).getEvidence(), equalTo(evidence));
		}
	}

	@Test
	public void passesIfAwsHostname() throws HttpMalformedHeaderException {
		String[] candidates = new String[] {
				// check the "borders" of private-IP-range-patterns
				"ip-9-255-255-255",
				"ip-11-0-0-0",
				"ip-172-15-255-255",
				"ip-172-32-0-0",
				"ip-192-167-255-255",
				"ip-192-169-0-0",
				// somewhere outside & between the private-IP-range-patterns
				"ip-8-8-8-8",
				"ip-26-10-3-11",
				"ip-84-168-27-12",
				"ip-127-0-0-1",		// the original said: "IP's including localhost" should we add it?
				"ip-186-27-16-2",
				"ip-255-255-255-255",
				// some invalid ones
				"ip-10",
				"ip-10-0-0",
				"ip-10-0-0:0",
				"ip-10/0-0-0",
				"ip-10-0\n0-0",
				"ip-10-0-0 0",
				"ip-10-0-0-a",
				"ip-999-0-0-0",
				"ip-10-999-0-0",
				"ip-10-0-756-0",
				"ip- 10-0-0-0 ",
				"ip-\n10-0-0-0\t",
				"10-0-0-0",
				"<img src='/img/AR-10-01-07-17.jpg'/>",  // taken from zaproxy/issues/2834
				// desired functionality?
				// since all the Amazon-samples i've seen start with a lowercase-'ip-': should we stay case-sensitive?
				"IP-10-0-0-0:",
		};
		for (String candidate : candidates) {
			HttpMessage msg = createHttpMessage(candidate);
			rule.scanHttpResponseReceive(msg, -1, createSource(msg));
		}
		assertThat(alertsRaised.size(), equalTo(0));
	}

}
