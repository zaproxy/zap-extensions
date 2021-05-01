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
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.pscanrules;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.List;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.users.User;

public class UsernameIdorScanRuleUnitTest extends PassiveScannerTest<UsernameIdorScanRule> {

    private HttpMessage msg;

    // Hashes in lower case for "guest" without quotes
    private static final String GUEST_MD5 = "084e0343a0486ff05530df6c705c8bb4";
    private static final String GUEST_SHA1 =
            "84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec";
    // Hash in lower case for "admin" without quotes
    private static final String ADMIN_MD5 = "21232f297a57a5a743894a0e4a801fc3";
    // Hash in lower case for "foobar" without quotes
    private static final String FOOBAR_MD2 = "3af4bb69e03489fc4ceebe50151d3e1a";

    @BeforeEach
    public void before() throws URIException {

        when(passiveScanData.getUsers()).thenReturn(Arrays.asList(new User(1, "guest")));

        HttpRequestHeader requestHeader = new HttpRequestHeader();
        requestHeader.setURI(new URI("http://example.com", false));

        msg = new HttpMessage();
        msg.setRequestHeader(requestHeader);
        UsernameIdorScanRule.setPayloadProvider(null);
    }

    @Override
    protected UsernameIdorScanRule createScanner() {
        return new UsernameIdorScanRule();
    }

    @Test
    public void shouldNotRaiseAlertIfResponseHasNoRelevantContent() {
        // Given
        msg.setResponseBody("Some text <h1>Some Title Element</h1>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(alertsRaised.size(), 0);
    }

    @Test
    public void shouldNotRaiseAlertIfResponseContainsIrrelevantHash() {
        // Given - "Guest" with a leading cap
        msg.setResponseBody(
                "Some text <h1>Some Title Element</h1><i>adb831a7fdd83dd1e2a309ce7591dff8</i>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(alertsRaised.size(), 0);
    }

    @Test
    public void shouldRaiseAlertIfResponseContainsRelevantMd5Hash() {
        // Given - Mixed case hash
        msg.setResponseBody(
                "Some text <h1>Some Title Element</h1><i>084E0343A0486fF05530DF6C705C8Bb4</i>");
        // When
        scanHttpResponseReceive(msg);
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
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(alertsRaised.size(), 1);
        assertEquals(alertsRaised.get(0).getEvidence(), GUEST_SHA1);
    }

    @Test
    public void shouldRaiseMultipleAlertsIfResponseContainsMultipleRelevantHashes() {
        // Given
        msg.setResponseBody(
                "Some text <h1>Some Title Element</h1><b>"
                        + GUEST_MD5
                        + "</b>"
                        + "<b>adb831a7fdd83dd1e2a309ce7591dff8</b>"
                        + "<br>"
                        + GUEST_SHA1
                        + "</b>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(alertsRaised.size(), 2);
        assertEquals(alertsRaised.get(0).getEvidence(), GUEST_SHA1);
        assertEquals(alertsRaised.get(1).getEvidence(), GUEST_MD5);
    }

    @Test
    public void shouldRaiseAlertIfResponseContainsRelevantHashInHeader() {
        // Given
        msg.getResponseHeader().setHeader("X-Test-Thing", GUEST_MD5);
        msg.setResponseBody(
                "Some text <h1>Some Title Element</h1><p>Lorem ipsum dolor "
                        + "sit amet, consectetur adipiscing elit. Nunc tempor mi et "
                        + "pulvinar convallis. Maecenas laoreet fermentum tempor. "
                        + "Nulla et.</p>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(alertsRaised.size(), 1);
        assertEquals(alertsRaised.get(0).getEvidence(), GUEST_MD5);
    }

    @Test
    public void shouldRaiseAlertIfResponseHasHashOfDefaultPayload() {
        // Given
        msg.getResponseHeader().setHeader("X-Test-Thing", ADMIN_MD5);
        msg.setResponseBody("Some text <h1>Some Title Element</h1>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(alertsRaised.size(), 1);
        assertEquals(alertsRaised.get(0).getEvidence(), ADMIN_MD5);
    }

    @Test
    public void shouldRaiseAlertIfResponseHasHashOfCustomPayload() {
        // Given
        msg.getResponseHeader().setHeader("X-Test-Thing", FOOBAR_MD2);
        msg.setResponseBody("Some text <h1>Some Title Element</h1>");
        List<String> testUsers = Arrays.asList("foobar");
        UsernameIdorScanRule.setPayloadProvider(() -> testUsers);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(alertsRaised.size(), 1);
        assertEquals(alertsRaised.get(0).getEvidence(), FOOBAR_MD2);
    }
}
