/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrulesAlpha;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.BasicConfigurator;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.extension.encoder.Base64;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;

public class Base64DisclosureUnitTest extends PassiveScannerTest<Base64Disclosure> {

    @BeforeClass
    public static void loggerSetup() {
        BasicConfigurator.configure();
    }

    @AfterClass
    public static void loggerReset() {
        BasicConfigurator.resetConfiguration();
    }

    @Override
    protected Base64Disclosure createScanner() {
        Base64Disclosure result = new Base64Disclosure();
        // that not every char-sequence is treated as Base64-encoded
        result.setAlertThreshold(AlertThreshold.OFF);
        return result;
    }

    private HttpMessage createMessage() throws URIException {
        HttpRequestHeader requestHeader = new HttpRequestHeader();
        requestHeader.setMethod("GET");
        requestHeader.setURI(new URI("https://example.com/fred/", false));

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(requestHeader);
        return msg;
    }

    @Test
    public void shouldNotRaiseAlertWhenBodyAndHeaderNotBase64Encoded()
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Content-Type: text;charset=UTF-8");
        msg.setResponseBody("not base64");

        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));

        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldRaiseInformationalAlertWhenBase64HasWrongPreamble()
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Content-Type: text;charset=UTF-8");
        // body is Base64 encoded, Cc91 when decoded in bytes starts with 0x09
        StringBuffer bodyBase64 = new StringBuffer();
        for (int i = 0; i < 6; i++) bodyBase64.append("Cc91f");
        msg.setResponseBody(bodyBase64.toString());

        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));

        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getDescription(),
                equalTo(Constant.messages.getString("pscanalpha.base64disclosure.desc")));
        assertThat(alertsRaised.get(0).getCweId(), equalTo(200));
    }

    @Test
    public void shouldRaiseInformationalAlertWhenBase64ValueHasMAC()
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        byte body[] = new byte[23];
        body[0] = -1; // preample[0]
        body[1] = 0x01; // preample[1]
        body[2] = 0x02; // unit32
        body[3] = 0x01; // value 1
        // fill the rest, that Base64-parser detects it
        for (int i = 4; i < body.length; i++) {
            body[i] = 0x04;
        }
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Content-Type: text;charset=UTF-8");
        msg.setResponseBody(Base64.encodeBytes(body));

        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));

        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getDescription(),
                equalTo(Constant.messages.getString("pscanalpha.base64disclosure.viewstate.desc")));
        assertThat(alertsRaised.get(0).getCweId(), equalTo(200));
    }

    @Test
    public void shouldRaiseAlertExternalControlWhenBase64ValueIsMACless()
            throws URIException, HttpMalformedHeaderException {

        HttpMessage msg = createMessage();
        byte body[] = new byte[23];
        body[0] = -1; // preample[0]
        body[1] = 0x01; // preample[1]
        body[2] = 0x1E; // string
        body[3] = 0x13; // stringsize (the rest of body)
        for (int i = 4; i < body.length; i++) {
            body[i] = 0x10;
        }

        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Content-Type: text;charset=UTF-8");
        msg.setResponseBody(Base64.encodeBytes(body));

        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));

        // Then
        assertThat(alertsRaised.size(), equalTo(2));
        assertThat(
                alertsRaised.get(1).getDescription(),
                equalTo(
                        Constant.messages.getString(
                                "pscanalpha.base64disclosure.viewstatewithoutmac.desc")));
        assertThat(alertsRaised.get(1).getCweId(), equalTo(642));
    }
}
