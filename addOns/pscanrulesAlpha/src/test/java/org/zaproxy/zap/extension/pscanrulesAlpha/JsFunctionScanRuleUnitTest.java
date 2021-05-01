/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;

public class JsFunctionScanRuleUnitTest extends PassiveScannerTest<JsFunctionScanRule> {

    @Override
    protected JsFunctionScanRule createScanner() {
        return new JsFunctionScanRule();
    }

    @Override
    public void setUpZap() throws Exception {
        super.setUpZap();

        Path xmlDir =
                Files.createDirectories(
                        Paths.get(Constant.getZapHome(), JsFunctionScanRule.FUNC_LIST_DIR));
        Path testFile = xmlDir.resolve(JsFunctionScanRule.FUNC_LIST_FILE);
        Files.write(testFile, Arrays.asList("# Test File", "bypassSecurityTrustHtml", "eval"));
    }

    @Test
    public void shouldAlertGivenFunctionInJavaScriptResponse()
            throws HttpMalformedHeaderException, URIException {
        // Given
        String body = "Some text <script>$eval()</script>\nLine 2\n";
        HttpMessage msg = createHttpMessageWithRespBody(body, "text/javascript;charset=ISO-8859-1");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertEquals("eval", alertsRaised.get(0).getEvidence());
    }

    @Test
    public void shouldAlertGivenFunctionInHtmlScriptElements()
            throws HttpMalformedHeaderException, URIException {

        // Given
        String body =
                "<h1>Some text <script>Some Html Element bypassSecurityTrustHtml()</script></h1>\n"
                        + "<b>No script here</b>\n";
        HttpMessage msg = createHttpMessageWithRespBody(body, "text/html;charset=ISO-8859-1");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertEquals("bypassSecurityTrustHtml", alertsRaised.get(0).getEvidence());
    }

    @Test
    public void shouldNotAlertGivenNoMatch() throws URIException, HttpMalformedHeaderException {
        // Given
        String body = "Some text <script>innocentFunction()</script>\nLine 2\n";
        HttpMessage msg = createHttpMessageWithRespBody(body, "text/javascript;charset=ISO-8859-1");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, empty());
    }

    @Test
    public void shouldNotAlertGivenEmptyBody() throws HttpMalformedHeaderException, URIException {

        // Given
        String body = "";
        HttpMessage msg = createHttpMessageWithRespBody(body, "text/html;charset=ISO-8859-1");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, empty());
    }

    @Test
    public void shouldAlertGivenCustomPayloadFunctionMatch()
            throws HttpMalformedHeaderException, URIException {
        // Given
        String body = "Some text <script>$badFunction()</script>\nLine 2\n";
        HttpMessage msg = createHttpMessageWithRespBody(body, "text/html;charset=ISO-8859-1");
        List<String> functions = Collections.singletonList("$badFunction");
        JsFunctionScanRule.setPayloadProvider(() -> functions);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertEquals("$badFunction", alertsRaised.get(0).getEvidence());
    }

    @Test
    public void shouldNotAlertGivenMatchOutsideScript()
            throws HttpMalformedHeaderException, URIException {
        // Given
        String body =
                "<h1>Some text <script>Something innocent happening here</script></h1>\n"
                        + "<b>You should not use bypassSecurityTrustHtml()</b>\n";
        HttpMessage msg = createHttpMessageWithRespBody(body, "text/html;charset=ISO-8859-1");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, empty());
    }

    @Test
    public void shouldAlertGivenMatchInSecondScript()
            throws HttpMalformedHeaderException, URIException {
        // Given
        String body =
                "<h1>Some text <script>Something innocent happening here</script></h1>\n"
                        + "<p><b>Just some words going on</b>\n"
                        + "<script>$eval()</script></p>\n";
        HttpMessage msg = createHttpMessageWithRespBody(body, "text/html;charset=ISO-8859-1");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertEquals("eval", alertsRaised.get(0).getEvidence());
    }

    @Test
    public void shouldAlertOnceGivenMultipleMatchesHTML()
            throws HttpMalformedHeaderException, URIException {
        // Given
        String body =
                "<h1>Some text <script>eval()</script></h1>\n"
                        + "<p><b>Just some words going on</b>\n"
                        + "<script>bypassSecurityTrustHtml()</script></p>\n";
        HttpMessage msg = createHttpMessageWithRespBody(body, "text/html;charset=ISO-8859-1");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertEquals("eval", alertsRaised.get(0).getEvidence());
    }

    @Test
    public void shouldAlertOnceGivenMultipleMatchesJS()
            throws HttpMalformedHeaderException, URIException {
        // Given
        String body = "Some text <script>eval()</script>\n" + "bypassSecurityTrustHtml()\n";
        HttpMessage msg = createHttpMessageWithRespBody(body, "text/javascript;charset=ISO-8859-1");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertEquals("bypassSecurityTrustHtml", alertsRaised.get(0).getEvidence());
    }

    private HttpMessage createHttpMessageWithRespBody(String responseBody, String contentType)
            throws HttpMalformedHeaderException, URIException {

        HttpRequestHeader requestHeader = new HttpRequestHeader();
        requestHeader.setURI(new URI("http://example.com", false));

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(requestHeader);
        msg.setResponseBody(responseBody);
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: "
                        + contentType
                        + "\r\n"
                        + "Content-Length: "
                        + responseBody.length()
                        + "\r\n");
        return msg;
    }
}
