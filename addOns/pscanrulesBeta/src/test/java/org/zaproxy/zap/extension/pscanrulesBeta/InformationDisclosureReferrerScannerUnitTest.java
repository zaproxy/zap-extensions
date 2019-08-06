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
package org.zaproxy.zap.extension.pscanrulesBeta;

import static org.junit.Assert.assertEquals;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;

public class InformationDisclosureReferrerScannerUnitTest
        extends PassiveScannerTest<InformationDisclosureReferrerScanner> {

    private static final String URI = "http://example.com/";
    private static final String BODY = "Some text in the response, doesn't matter.\nLine 2\n";
    private HttpMessage msg;

    @Override
    protected InformationDisclosureReferrerScanner createScanner() {
        return new InformationDisclosureReferrerScanner();
    }

    protected HttpMessage createHttpMessageWithRespBody(String responseBody, String testReferer)
            throws HttpMalformedHeaderException, URIException {

        HttpRequestHeader requestHeader = new HttpRequestHeader();
        requestHeader.setURI(new URI(URI, false));
        requestHeader.setHeader("Referer", testReferer);

        msg = new HttpMessage();
        msg.setRequestHeader(requestHeader);
        msg.setResponseBody(responseBody);
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/plain\r\n"
                        + "Content-Length: "
                        + responseBody.length()
                        + "\r\n");
        return msg;
    }

    @Override
    public void setUpZap() throws Exception {
        super.setUpZap();

        Path xmlDir =
                Files.createDirectories(
                        Paths.get(
                                Constant.getZapHome(),
                                InformationDisclosureReferrerScanner.URLSensitiveInformationDir));
        Path testFile =
                xmlDir.resolve(InformationDisclosureReferrerScanner.URLSensitiveInformationFile);
        Files.write(testFile, Arrays.asList(" user", " Password ", "# notused", "session "));
    }

    @Test
    public void noAlertOnSelfReference() throws HttpMalformedHeaderException, URIException {

        // Given
        String testReferer = URI + "?password=whatsup&hl=en";
        HttpMessage msg = createHttpMessageWithRespBody(BODY, testReferer);

        // When
        rule.scanHttpRequestSend(msg, -1);

        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    public void sensitiveInfoInReferer() throws HttpMalformedHeaderException, URIException {

        // Given
        String testReferer = "http://foo.com/?passWord=whatsup&hl=en";
        HttpMessage msg = createHttpMessageWithRespBody(BODY, testReferer);

        // When
        rule.scanHttpRequestSend(msg, -1);

        // Then
        assertEquals(1, alertsRaised.size());
    }

    @Test
    public void noSensitiveInfoInReferer() throws HttpMalformedHeaderException, URIException {

        // Given
        String testReferer = "http://foo.com/?words=whatsup&hl=en";
        HttpMessage msg = createHttpMessageWithRespBody(BODY, testReferer);

        // When
        rule.scanHttpRequestSend(msg, -1);

        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    public void creditCardInReferer() throws HttpMalformedHeaderException, URIException {

        // Given
        String testReferer = "http://foo.com/?docid=6011000990139424&hl=en";
        HttpMessage msg = createHttpMessageWithRespBody(BODY, testReferer);

        // When
        rule.scanHttpRequestSend(msg, -1);

        // Then
        assertEquals(1, alertsRaised.size());
    }

    @Test
    public void noCreditCardInReferer() throws HttpMalformedHeaderException, URIException {

        // Given
        String testReferer = "http://foo.com/?docid=applepie&hl=en";
        HttpMessage msg = createHttpMessageWithRespBody(BODY, testReferer);

        // When
        rule.scanHttpRequestSend(msg, -1);

        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    public void emailAddressInReferer() throws HttpMalformedHeaderException, URIException {

        // Given
        String testReferer = "http://foo.com/?docid=example@gmail.com&hl=en";
        HttpMessage msg = createHttpMessageWithRespBody(BODY, testReferer);

        // When
        rule.scanHttpRequestSend(msg, -1);

        // Then
        assertEquals(1, alertsRaised.size());
    }

    @Test
    public void noEmailAddressInReferer() throws HttpMalformedHeaderException, URIException {

        // Given
        String testReferer = "http://foo.com/?docid=examplegmail.com&hl=en";
        HttpMessage msg = createHttpMessageWithRespBody(BODY, testReferer);

        // When
        rule.scanHttpRequestSend(msg, -1);

        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    public void SSNInReferer() throws HttpMalformedHeaderException, URIException {

        // Given
        String testReferer = "http://foo.com/?docid=000-00-0000&hl=en";
        HttpMessage msg = createHttpMessageWithRespBody(BODY, testReferer);

        // When
        rule.scanHttpRequestSend(msg, -1);

        // Then
        assertEquals(1, alertsRaised.size());
    }

    @Test
    public void noSSNInReferer() throws HttpMalformedHeaderException, URIException {

        // Given
        String testReferer = "http://foo.com/?docid=ssn-no-here&hl=en";
        HttpMessage msg = createHttpMessageWithRespBody(BODY, testReferer);

        // When
        rule.scanHttpRequestSend(msg, -1);

        // Then
        assertEquals(0, alertsRaised.size());
    }
}
