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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

public class InfoPrivateAddressDisclosureScanRuleUnitTest
        extends PassiveScannerTest<InfoPrivateAddressDisclosureScanRule> {
    private static final String URI = "https://www.example.com/";

    @Override
    protected InfoPrivateAddressDisclosureScanRule createScanner() {
        return new InfoPrivateAddressDisclosureScanRule();
    }

    @Test
    public void alertsIfPrivateIp() throws HttpMalformedHeaderException {
        // ip as candidate / evidence
        String[][] data =
                new String[][] {
                    // IPs defined in RFC 1918
                    {"10.0.0.0", "10.0.0.0"},
                    {"10.10.10.10", "10.10.10.10"},
                    {"10.255.255.255", "10.255.255.255"},
                    {"172.16.0.0", "172.16.0.0"},
                    {"172.25.16.32", "172.25.16.32"},
                    {"172.31.255.255", "172.31.255.255"},
                    {"192.168.0.0", "192.168.0.0"},
                    {"192.168.36.127", "192.168.36.127"},
                    {"192.168.255.255", "192.168.255.255"},

                    // some other stuff
                    {"10.0.0.0:", "10.0.0.0"},
                    {"10.0.0.0:6553", "10.0.0.0:6553"},
                    {" 10.0.0.0 ", "10.0.0.0"},
                    {"/10.0.0.0.", "10.0.0.0"},
                    {";10.0.0.0,", "10.0.0.0"},
                    {"\n10.0.0.0\t", "10.0.0.0"},
                    {"\n10.0.0.0\t", "10.0.0.0"},
                    {"10.0.0.0:bla", "10.0.0.0"},
                    {"15.10.0.0.0.12.27", "10.0.0.0"},
                    {"100.10.0.0.0.10.12", "10.0.0.0"},
                    {"255.10.0.0.0:6555", "10.0.0.0:6555"},
                    {"10.0.0.0:128", "10.0.0.0:128"},
                    {"ip-10.0.0.0", "10.0.0.0"},
                    {"IP-10.0.0.0", "10.0.0.0"},
                    {"172.30.10.10.10.0.0.0", "172.30.10.10"},
                    {"172.30.10.10.10.0.0.0:6555", "172.30.10.10"}
                };
        for (int i = 0; i < data.length; i++) {
            String candidate = data[i][0];
            String evidence = data[i][1];
            HttpMessage msg = createHttpMessage(candidate);
            scanHttpResponseReceive(msg);

            assertThat(candidate, alertsRaised.size(), equalTo(i + 1));
            assertThat(alertsRaised.get(i).getEvidence(), equalTo(evidence));
            validateAlert(alertsRaised.get(i));
        }
    }

    @Test
    public void shouldIgnoreRequestedPrivateIpByDefault() throws Exception {
        // Given
        // ip and aws-hostname which get concatenated with the ports as candidates
        String[] ipHost = new String[] {"10.0.2.2", "ip-10-0-2-2"};
        String[] ports = new String[] {":45876", ":8081", ":98", ""};
        for (int pi = 0; pi < ports.length; pi++) {
            for (int ii = 0; ii < ipHost.length; ii++) {
                alertsRaised.clear();
                String candidate = ipHost[ii] + ports[pi];
                HttpMessage msg = createHttpMessage(candidate, candidate);
                // When
                scanHttpResponseReceive(msg);
                // Then
                assertThat(candidate, alertsRaised.size(), equalTo(0));
            }
        }
    }

    @Test
    public void shouldAlertRequestedPrivateIpIfLowAlertThreshold()
            throws HttpMalformedHeaderException {
        // Given
        String privateIp = "192.168.36.127";
        String requestUri = "https://" + privateIp + ":8123/";
        HttpMessage msg = createHttpMessage(requestUri, privateIp);
        rule.setAlertThreshold(AlertThreshold.LOW);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(equalTo(1)));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(privateIp));
        validateAlert(requestUri, alertsRaised.get(0));
    }

    @Test
    public void passesIfNonPrivateOrInvalidIp() throws HttpMalformedHeaderException {
        String[] candidates =
                new String[] {
                    // the "borders" of private IP ranges
                    "9.255.255.255",
                    "11.0.0.0",
                    "172.15.255.255",
                    "172.32.0.0",
                    "192.167.255.255",
                    "192.169.0.0",
                    // outside & between the private ranges
                    "8.8.8.8",
                    "26.10.3.11",
                    "84.168.27.12",
                    "127.0.0.1",
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
                    "ip-10-0-0-256",
                    // no word boundaries
                    "2050:10.0.0.0bla",
                    "205010.0.0.0:bla",
                    "abcd10.0.0.0bla",
                    "abcd10.0.0.999",
                    "ip-10.0.0.9999",
                };
        for (String candidate : candidates) {
            HttpMessage msg = createHttpMessage(candidate);
            scanHttpResponseReceive(msg);
        }
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void alertsIfPrivIpAndAddsPortToEvidence() throws HttpMalformedHeaderException {
        // ip and aws-hostname which get concatenated with the ports as candidates
        String[] ipHost = new String[] {"10.0.0.0", "ip-10-0-0-0"};
        // several ports in the range 0-65535
        String[] ports =
                new String[] {
                    ":0", ":1", ":6", ":9", ":10", ":25", ":99", ":100", ":443", ":999", ":1000",
                    ":8080", ":9999", ":10000", ":16443", ":19999", ":20000", ":24128", ":29999",
                    ":30000", ":35097", ":39999", ":40000", ":41962", ":49999", ":50000", ":56481",
                    ":59999", ":61000", ":61443", ":61999", ":62000", ":62128", ":62999", ":63000",
                    ":63097", ":63999", ":64000", ":64962", ":64999", ":65000", ":65010", ":65029",
                    ":65100", ":65210", ":65329", ":65400", ":65410", ":65499", ":65500", ":65510",
                    ":65518", ":65520", ":65529", ":65535"
                };
        for (int pi = 0; pi < ports.length; pi++) {
            for (int ii = 0; ii < ipHost.length; ii++) {
                alertsRaised.clear();
                String candidate = ipHost[ii] + ports[pi];
                HttpMessage msg = createHttpMessage(candidate);
                scanHttpResponseReceive(msg);

                assertThat(candidate, alertsRaised.size(), equalTo(1));
                assertThat(alertsRaised.get(0).getEvidence(), equalTo(candidate));
                validateAlert(alertsRaised.get(0));
            }
        }
    }

    @Test
    public void alertsIfPrivIpAndDropsPortNoInEvidence() throws HttpMalformedHeaderException {
        // ip and aws-hostname which get concatenated with the ports as candidates
        String[] ipHost = new String[] {"10.0.0.0", "ip-10-0-0-0"};
        // several ports to be ignored
        String[] ports =
                new String[] {
                    ":65536",
                    ":78736",
                    ":99999",
                    ":4A3",
                    //				// no word boundaries
                    ":600000",
                    ":649999",
                    ":64999A"
                };
        for (int pi = 0; pi < ports.length; pi++) {
            for (int ii = 0; ii < ipHost.length; ii++) {
                alertsRaised.clear();
                String candidate = ipHost[ii] + ports[pi];
                HttpMessage msg = createHttpMessage(candidate);
                scanHttpResponseReceive(msg);

                assertThat(candidate, alertsRaised.size(), equalTo(1));
                assertThat(alertsRaised.get(0).getEvidence(), equalTo(ipHost[ii]));
                validateAlert(alertsRaised.get(0));
            }
        }
    }

    @Test
    public void alertsIfPrivateAwsHostname() throws HttpMalformedHeaderException {
        // ip as candidate / evidence
        String[][] data =
                new String[][] {
                    // body text               evidence
                    // Pattern of IPs defined in RFC 1918
                    {"ip-10-0-0-0", "ip-10-0-0-0"},
                    {"ip-10-10-10-10", "ip-10-10-10-10"},
                    {"ip-10-255-255-255", "ip-10-255-255-255"},
                    {"ip-172-16-0-0", "ip-172-16-0-0"},
                    {"ip-172-25-16-32", "ip-172-25-16-32"},
                    {"ip-172-31-255-255", "ip-172-31-255-255"},
                    {"ip-192-168-0-0", "ip-192-168-0-0"},
                    {"ip-192-168-36-127", "ip-192-168-36-127"},
                    {"ip-192-168-255-255", "ip-192-168-255-255"},
                    // other stuff
                    {"ip-10-0-0-0:", "ip-10-0-0-0"},
                    {"ip-10-0-0-0:6553", "ip-10-0-0-0:6553"},
                    {" ip-10-0-0-0 ", "ip-10-0-0-0"},
                    {"/ip-10-0-0-0-", "ip-10-0-0-0"},
                    {";ip-10-0-0-0,", "ip-10-0-0-0"},
                    {"\nip-10-0-0-0\t", "ip-10-0-0-0"},
                    {"ip-10-0-0-0:bla", "ip-10-0-0-0"},
                    {"15-ip-10-0-0-0-12-27", "ip-10-0-0-0"},
                    {"255:ip-10-0-0-0:6555", "ip-10-0-0-0:6555"},
                    {"/ip-10-01-07-17.jpg", "ip-10-01-07-17"},
                };
        for (int i = 0; i < data.length; i++) {
            String candidate = data[i][0];
            String evidence = data[i][1];
            HttpMessage msg = createHttpMessage(candidate);
            scanHttpResponseReceive(msg);

            assertThat(candidate, alertsRaised.size(), equalTo(i + 1));
            assertThat(alertsRaised.get(i).getEvidence(), equalTo(evidence));
            validateAlert(alertsRaised.get(i));
        }
    }

    @Test
    public void passesIfInvalidAwsHostname() throws HttpMalformedHeaderException {
        String[] candidates =
                new String[] {
                    // "outside borders" of private-IP-range-patterns
                    "ip-9-255-255-255",
                    "ip-11-0-0-0",
                    "ip-172-15-255-255",
                    "ip-172-32-0-0",
                    "ip-192-167-255-255",
                    "ip-192-169-0-0",
                    // outside & betw. private-IP-range-patterns
                    "ip-8-8-8-8",
                    "ip-26-10-3-11",
                    "ip-84-168-27-12",
                    "ip-127-0-0-1",
                    "ip-186-27-16-2",
                    "ip-255-255-255-255",
                    // some invalid IP ones
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
                    // others
                    "ip- 10-0-0-0 ",
                    "ip-\n10-0-0-0\t",
                    "10-0-0-0",
                    "2050ip-10-0-0-0bla",
                    "gossip-10-0-0-0bla",
                    "ip-10-0-0-999",
                    "ip-10-0-0-9999999",
                    "IP-10-0-0-0:",
                    "/IP-10-01-07-17.jpg",
                };
        for (String candidate : candidates) {
            HttpMessage msg = createHttpMessage(candidate);
            scanHttpResponseReceive(msg);
            assertThat(candidate, alertsRaised.size(), equalTo(0));
        }
    }

    @Test
    public void alertsWithJustTheFirstEvidenceIfPrivIpAndPrivHostname()
            throws HttpMalformedHeaderException {
        // candidate, evidence, otherInfo
        String[][] data =
                new String[][] {
                    {"10.0.0.0:128 ip-192-168-0-0", "10.0.0.0:128", "10.0.0.0:128ip-192-168-0-0"},
                    {
                        "ip-10-0-0-0:128:192.168.0.0",
                        "ip-10-0-0-0:128",
                        "ip-10-0-0-0:128192.168.0.0"
                    },
                    {
                        "172.16.0.0/ip-10-0-0-0:128:192.168.0.0",
                        "172.16.0.0",
                        "172.16.0.0ip-10-0-0-0:128192.168.0.0"
                    }
                };
        for (int i = 0; i < data.length; i++) {
            String candidate = data[i][0];
            HttpMessage msg = createHttpMessage(candidate);
            scanHttpResponseReceive(msg);

            assertThat(candidate, alertsRaised.size(), equalTo(i + 1));
            assertThat(alertsRaised.get(i).getEvidence(), equalTo(data[i][1]));
            validateAlert(alertsRaised.get(i));

            String otherInfo = alertsRaised.get(i).getOtherInfo().replaceAll("\\n", "");
            assertThat(otherInfo, equalTo(data[i][2]));
        }
    }

    @Test
    public void testOfScanHttpRequestSend() throws HttpMalformedHeaderException {
        // the method should do nothing (test just for code coverage)
        scanHttpRequestSend(createHttpMessage("10.0.2.2"));
        assertThat(alertsRaised.size(), equalTo(0));
    }

    private static void validateAlert(Alert alert) {
        validateAlert(URI, alert);
    }

    private static void validateAlert(String requestUri, Alert alert) {
        assertThat(alert.getPluginId(), equalTo(00002));
        assertThat(alert.getRisk(), equalTo(Alert.RISK_LOW));
        assertThat(alert.getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
        assertThat(alert.getUri(), equalTo(requestUri));
    }

    private HttpMessage createHttpMessage(String body) throws HttpMalformedHeaderException {
        return createHttpMessage(URI, body);
    }

    private HttpMessage createHttpMessage(String requestUri, String body)
            throws HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage();
        requestUri = requestUri.startsWith("http") ? requestUri : "http://" + requestUri;
        msg.setRequestHeader("GET " + requestUri + " HTTP/1.1");
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n");
        msg.setResponseBody(body);
        return msg;
    }
}
