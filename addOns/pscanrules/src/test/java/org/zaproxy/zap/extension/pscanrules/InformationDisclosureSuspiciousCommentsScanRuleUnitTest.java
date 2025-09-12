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
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.addon.commonlib.ResourceIdentificationUtils;

class InformationDisclosureSuspiciousCommentsScanRuleUnitTest
        extends PassiveScannerTest<InformationDisclosureSuspiciousCommentsScanRule> {

    @Override
    protected InformationDisclosureSuspiciousCommentsScanRule createScanner() {
        InformationDisclosureSuspiciousCommentsScanRule.setPayloadProvider(null);
        return new InformationDisclosureSuspiciousCommentsScanRule();
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
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(tags.size(), is(equalTo(4)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_INFO_05_CONTENT_LEAK.getTag()),
                is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.PENTEST.getTag()), is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_INFO_05_CONTENT_LEAK.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_INFO_05_CONTENT_LEAK.getValue())));
    }

    @Test
    void shouldNotAlertOnSuspiciousValuesInJavaScriptResponse()
            throws HttpMalformedHeaderException, URIException {

        // Given
        String line1 = "myArray = [\"success\",\"FIXME\"]";
        String body = line1 + "\nLine 2\n";
        HttpMessage msg = createHttpMessageWithRespBody(body, "text/javascript;charset=ISO-8859-1");

        assertTrue(msg.getResponseHeader().isText());
        assertTrue(ResourceIdentificationUtils.isJavaScript(msg));
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(0, alertsRaised.size());
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "/* FIXME: admin:admin01$ */",
                "/*FIXME: admin:admin01$*/",
                "// FIXME: admin:admin01$",
                "//FIXME: admin:admin01$"
            })
    void shouldAlertOnSuspiciousCommentInJavaScriptResponseWithComment(String comment)
            throws HttpMalformedHeaderException, URIException {

        // Given
        String line1 = "myArray = [\"success\",\"FIXME\"]";
        String line2 = "\n" + comment;
        String body = line1 + line2 + "\nLine 3\n";
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
                wrapEvidenceOtherInfo("\\bFIXME\\b", comment, 1),
                alertsRaised.get(0).getOtherInfo());
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
        String comment = "// FIXME: DO something";
        String line1 = "Some text <script>Some Script Element " + comment;
        String line2 = "// FIXME: DO something else </script>";
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
                wrapEvidenceOtherInfo("\\bFIXME\\b", comment, 1),
                alertsRaised.get(0).getOtherInfo());
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
    void shouldAlertOnSuspiciousCommentInHtmlScriptElementWithComment()
            throws HttpMalformedHeaderException, URIException {

        // Given
        String comment = "// todo DO something";
        String script = "<script>Some Script Element " + comment + "\n</script>";
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
                wrapEvidenceOtherInfo("\\bTODO\\b", comment, 1),
                alertsRaised.get(0).getOtherInfo());
    }

    @Test
    void shouldNotAlertOnSuspiciousContentInHtmlScriptElement()
            throws HttpMalformedHeaderException, URIException {
        // Given
        String script = "<script>myArray = [\"admin\", \"password\"]\n</script>";
        String body = "<h1>Some text " + script + "</h1>\n<b>No script here</b>\n";
        HttpMessage msg = createHttpMessageWithRespBody(body, "text/html;charset=ISO-8859-1");

        assertTrue(msg.getResponseHeader().isText());
        assertFalse(ResourceIdentificationUtils.isJavaScript(msg));
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(0, alertsRaised.size());
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
    void shouldAlertOnSuspiciousCommentProvidedByCustomPayload()
            throws HttpMalformedHeaderException, URIException {

        // Given
        Iterable<String> customPayloads = List.of("zap_internal", "my_insights");
        String body =
                "<h1>Some text <!--MY_INSIGHTS: This is a test --></h1>\n"
                        + "<b>Welcome to Zaproxy</b>\n";
        HttpMessage msg = createHttpMessageWithRespBody(body, "text/html;charset=ISO-8859-1");

        // When
        InformationDisclosureSuspiciousCommentsScanRule.setPayloadProvider(() -> customPayloads);
        scanHttpResponseReceive(msg);

        // Then
        assertEquals(1, alertsRaised.size());
    }

    @Test
    void shouldAlertOnSuspiciousValuesInJavascriptSingleLineComment()
            throws HttpMalformedHeaderException, URIException {
        shouldAlertOnSuspiciousCommentInJavascriptContent(
                """
                function fooFunction() {
                  var bar = 'Some text // ADMINISTRATOR fake comment';
                }
                """);
    }

    @Test
    void shouldAlertOnSuspiciousValuesInJavascriptBlockComment()
            throws HttpMalformedHeaderException, URIException {
        shouldAlertOnSuspiciousCommentInJavascriptContent(
                """
                function fooFunction() {
                  var bar = 'Some text /* ADMINISTRATOR fake comment */';
                }
                """);
    }

    private void shouldAlertOnSuspiciousCommentInJavascriptContent(String body)
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createHttpMessageWithRespBody(body, "application/javascript");
        InformationDisclosureSuspiciousCommentsScanRule.setPayloadProvider(
                () -> InformationDisclosureSuspiciousCommentsScanRule.DEFAULT_PAYLOADS);
        // When
        scanHttpResponseReceive(msg);
        // Then - Alert since we aren't yet actually parsing the JS
        assertThat(alertsRaised.size(), is(equalTo(1)));
    }

    @Test
    void shouldNotAlertIfNeitherCustomNorStandardPayloadsFound()
            throws HttpMalformedHeaderException, URIException {

        // Given
        Iterable<String> customPayloads = List.of("zap_internal", "my_insights");
        String body =
                "<h1>Some text <!-- Nothing special here --></h1>\n"
                        + "<b>Welcome to Zaproxy</b>\n";
        HttpMessage msg = createHttpMessageWithRespBody(body, "text/html;charset=ISO-8859-1");

        assertTrue(msg.getResponseHeader().isText());
        assertFalse(ResourceIdentificationUtils.isJavaScript(msg));

        // When
        InformationDisclosureSuspiciousCommentsScanRule.setPayloadProvider(() -> customPayloads);
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

    @Test
    void shouldNotAlertIfResponseIsTextButReallyFontUrl()
            throws HttpMalformedHeaderException, URIException {
        // Given
        HttpMessage msg =
                createHttpMessageWithRespBody(
                        "Some text <script>Some Script Element FixMe: DO something </script>\nLine 2\n",
                        "text/html");
        msg.getRequestHeader().setURI(new URI("http://example.com/shop-icons.woof", false));
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    void shouldHaveExpectedExample() {
        // Given / When
        List<Alert> alerts = rule.getExampleAlerts();
        // Then
        assertThat(alerts.size(), is(equalTo(1)));
        Alert alert = alerts.get(0);
        assertThat(alert.getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
        assertThat(
                alert.getOtherInfo(),
                is(
                        equalTo(
                                Constant.messages.getString(
                                        "pscanrules.informationdisclosuresuspiciouscomments.otherinfo",
                                        "\\bFIXME\\b",
                                        "<!-- FixMe: cookie: root=true; Secure -->"))));
        assertThat(alert.getEvidence(), is(equalTo("FixMe")));
        assertThat(alert.getCweId(), is(equalTo(615)));
        Map<String, String> tags = alert.getTags();
        assertThat(tags.size(), is(equalTo(6)));
        assertThat(tags, hasKey("CWE-615"));
        assertThat(tags, hasKey(CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getTag()));
        assertThat(tags, hasKey(CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED.getTag()));
        assertThat(tags, hasKey(CommonAlertTag.WSTG_V42_INFO_05_CONTENT_LEAK.getTag()));
        assertThat(tags, hasKey(CommonAlertTag.CUSTOM_PAYLOADS.getTag()));
        assertThat(tags, hasKey(PolicyTag.PENTEST.getTag()));
    }

    private static String wrapEvidenceOtherInfo(String evidence, String info, int count) {
        if (count == 1) {
            return "The following pattern was used: "
                    + evidence
                    + " and was detected in likely comment: \""
                    + info
                    + "\", see evidence field for the suspicious comment/snippet.";
        }
        return "The following pattern was used: "
                + evidence
                + " and was detected "
                + count
                + " times, the first in likely comment: \""
                + info
                + "\", see evidence field for the suspicious comment/snippet.";
    }
}
