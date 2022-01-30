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
package org.zaproxy.zap.extension.pscanrules;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.ResourceIdentificationUtils;

class InformationDisclosureSuspiciousCommentsScanRuleUnitTest
        extends PassiveScannerTest<InformationDisclosureSuspiciousCommentsScanRule> {

    @Override
    protected InformationDisclosureSuspiciousCommentsScanRule createScanner() {
        return new InformationDisclosureSuspiciousCommentsScanRule();
    }

    @Override
    public void setUpZap() throws Exception {
        super.setUpZap();

        Path xmlDir =
                Files.createDirectories(
                        Paths.get(
                                Constant.getZapHome(),
                                InformationDisclosureSuspiciousCommentsScanRule
                                        .suspiciousCommentsListDir));
        Path testFile =
                xmlDir.resolve(
                        InformationDisclosureSuspiciousCommentsScanRule.suspiciousCommentsListFile);
        Files.write(testFile, Arrays.asList("# FixMeNot", "  FixMe  ", "TODO", "\t "));
    }

    protected HttpMessage createHttpMessageWithRespBody(String responseBody, String contentType)
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

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(200)));
        assertThat(wasc, is(equalTo(13)));
        assertThat(tags.size(), is(equalTo(2)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED.getValue())));
    }

    @Test
    void shouldAlertOnSuspiciousCommentInJavaScriptResponse()
            throws HttpMalformedHeaderException, URIException {

        // Given
        String line1 = "Some text <script>Some Script Element FIXME: DO something </script>";
        String body = line1 + "\nLine 2\n";
        HttpMessage msg = createHttpMessageWithRespBody(body, "text/javascript;charset=ISO-8859-1");

        assertTrue(msg.getResponseHeader().isText());
        assertTrue(ResourceIdentificationUtils.isJavaScript(msg));

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertEquals(1, alertsRaised.size());
        assertEquals(Alert.CONFIDENCE_LOW, alertsRaised.get(0).getConfidence());
        assertEquals("FIXME", alertsRaised.get(0).getEvidence());
        assertEquals(
                wrapEvidenceOtherInfo("\\bFixMe\\b", line1, 1), alertsRaised.get(0).getOtherInfo());
    }

    @Test
    void shouldNotAlertOnSuspiciousCommentIsPartOfWordInJavaScriptResponse()
            throws HttpMalformedHeaderException, URIException {

        // Given
        String body =
                "Some text <script>Some Script Element FixMeNot: DO something </script>\nLine 2\n";
        HttpMessage msg = createHttpMessageWithRespBody(body, "text/javascript;charset=ISO-8859-1");

        assertTrue(msg.getResponseHeader().isText());
        assertTrue(ResourceIdentificationUtils.isJavaScript(msg));

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    void shouldCreateOneAlertforMultipleAndEqualSuspiciousComments()
            throws HttpMalformedHeaderException, URIException {

        // Given
        String line1 = "Some text <script>Some Script Element FIXME: DO something";
        String line2 = "FIXME: DO something else </script>";
        String body = line1 + "\n" + line2 + "\nLine 2\n";
        HttpMessage msg = createHttpMessageWithRespBody(body, "text/javascript;charset=ISO-8859-1");

        assertTrue(msg.getResponseHeader().isText());
        assertTrue(ResourceIdentificationUtils.isJavaScript(msg));

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertEquals(1, alertsRaised.size());
        assertEquals(Alert.CONFIDENCE_LOW, alertsRaised.get(0).getConfidence());
        assertEquals("FIXME", alertsRaised.get(0).getEvidence());
        // detected 2 times, the first in the element
        assertEquals(
                wrapEvidenceOtherInfo("\\bFixMe\\b", line1, 2), alertsRaised.get(0).getOtherInfo());
    }

    @Test
    void shouldNotAlertWithoutSuspiciousCommentInJavaScriptResponse()
            throws HttpMalformedHeaderException, URIException {

        // Given
        String body = "Some <script>text, nothing suspicious here...</script>\nLine 2\n";
        HttpMessage msg = createHttpMessageWithRespBody(body, "text/javascript;charset=ISO-8859-1");

        assertTrue(msg.getResponseHeader().isText());
        assertTrue(ResourceIdentificationUtils.isJavaScript(msg));

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    void shouldAlertOnSuspiciousCommentInHtmlScriptElements()
            throws HttpMalformedHeaderException, URIException {

        // Given
        String script = "<script>Some Html Element todo DO something </script>";
        String body = "<h1>Some text " + script + "</h1>\n<b>No script here</b>\n";
        HttpMessage msg = createHttpMessageWithRespBody(body, "text/html;charset=ISO-8859-1");

        assertTrue(msg.getResponseHeader().isText());
        assertFalse(ResourceIdentificationUtils.isJavaScript(msg));

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertEquals(1, alertsRaised.size());
        assertEquals(Alert.CONFIDENCE_LOW, alertsRaised.get(0).getConfidence());
        assertEquals(
                wrapEvidenceOtherInfo("\\bTODO\\b", script, 1), alertsRaised.get(0).getOtherInfo());
    }

    @Test
    void shouldNotAlertWithoutSuspiciousCommentInHtmlScriptElements()
            throws HttpMalformedHeaderException, URIException {

        // Given
        String body =
                "<h1>Some text <script>Some Html Element Fix: DO something </script></h1>\n"
                        + "<b>No script here</b>\n";
        HttpMessage msg = createHttpMessageWithRespBody(body, "text/html;charset=ISO-8859-1");

        assertTrue(msg.getResponseHeader().isText());
        assertFalse(ResourceIdentificationUtils.isJavaScript(msg));

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    void shouldAlertOnSuspiciousCommentInHtmlComments()
            throws HttpMalformedHeaderException, URIException {

        // Given
        String body =
                "<h1>Some text <!--Some Html comment FixMe: DO something --></h1>\n"
                        + "<b>No script here</b>\n";
        HttpMessage msg = createHttpMessageWithRespBody(body, "text/html;charset=ISO-8859-1");

        assertTrue(msg.getResponseHeader().isText());
        assertFalse(ResourceIdentificationUtils.isJavaScript(msg));

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertEquals(1, alertsRaised.size());
    }

    @Test
    void shouldNotAlertWhenNoSuspiciousCommentInHtmlComments()
            throws HttpMalformedHeaderException, URIException {

        // Given
        String body =
                "<h1>Some text <!--Some Html comment Fix: DO something --></h1>\n"
                        + "<b>No script here</b>\n";
        HttpMessage msg = createHttpMessageWithRespBody(body, "text/html;charset=ISO-8859-1");

        assertTrue(msg.getResponseHeader().isText());
        assertFalse(ResourceIdentificationUtils.isJavaScript(msg));

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    void shouldNotAlertIfResponseIsEmpty() throws HttpMalformedHeaderException, URIException {

        // Given
        HttpMessage msg = createHttpMessageWithRespBody("", "text/html;charset=ISO-8859-1");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    void shouldNotAlertIfResponseIsNotText() throws HttpMalformedHeaderException, URIException {

        // Given
        HttpMessage msg =
                createHttpMessageWithRespBody(
                        "Some text <script>Some Script Element FixMe: DO something </script>\nLine 2\n",
                        "application/octet-stream;charset=ISO-8859-1");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertEquals(0, alertsRaised.size());
    }

    private static String wrapEvidenceOtherInfo(String evidence, String info, int count) {
        if (count == 1) {
            return "The following pattern was used: "
                    + evidence
                    + " and was detected in the element starting with: \""
                    + info
                    + "\", see evidence field for the suspicious comment/snippet.";
        }
        return "The following pattern was used: "
                + evidence
                + " and was detected "
                + count
                + " times, the first in the element starting with: \""
                + info
                + "\", see evidence field for the suspicious comment/snippet.";
    }
}
