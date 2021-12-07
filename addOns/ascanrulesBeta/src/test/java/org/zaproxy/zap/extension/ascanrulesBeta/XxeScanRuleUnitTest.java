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
package org.zaproxy.zap.extension.ascanrulesBeta;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.io.File;
import java.io.IOException;
import java.text.MessageFormat;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.stream.Collectors;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.db.paros.ParosTableHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.testutils.NanoServerHandler;

class XxeScanRuleUnitTest extends ActiveScannerTest<XxeScanRule> {

    @BeforeAll
    static void setUpCallbacks() {
        HistoryReference.setTableHistory(new ParosTableHistory());
    }

    @Override
    protected XxeScanRule createScanner() {
        return new XxeScanRule();
    }

    @Test
    void replaceElementAndRemoveHeader() {
        // Given
        String requestBody = "<?xml version=\"1.0\"?><comment><text>\ntest\n</text></comment>";
        // When
        String payload = XxeScanRule.createLfrPayload(requestBody);
        // Then
        String expectedPayload =
                XxeScanRule.ATTACK_HEADER + "<comment><text>&zapxxe;</text></comment>";
        assertThat(payload, is(expectedPayload));
    }

    @Test
    void doNotReplaceAttributes() {
        // Given
        String requestBody =
                "<?xml version=\"1.0\"?><comment><text abc=\"123\">test</text></comment>";
        // When
        String payload = XxeScanRule.createLfrPayload(requestBody);
        // Then
        String expectedPayload =
                XxeScanRule.ATTACK_HEADER + "<comment><text abc=\"123\">&zapxxe;</text></comment>";
        assertThat(payload, is(expectedPayload));
    }

    @Test
    void replaceMultipleElementsAndRemoveHeader() {
        // Given
        String sampleXmlMessage = getXmlResource("xxescanrule/SampleXml.txt");
        String requestBody = "\n" + "<?xml version=\"1.0\"?>\n" + sampleXmlMessage;
        // When
        String payload = XxeScanRule.createLfrPayload(requestBody);
        // Then
        String expectedPayload =
                XxeScanRule.ATTACK_HEADER
                        + "\n"
                        + "\n"
                        + "<comments>\n"
                        + "    <comment>\n"
                        + "    <text>&zapxxe;</text>\n"
                        + "    </comment>\n"
                        + "\n"
                        + "    <comment>\n"
                        + "    <text>&zapxxe;</text>\n"
                        + "    </comment>\n"
                        + "    <comment>\n"
                        + "\n"
                        + "<otherValue>&zapxxe;</otherValue>\n"
                        + "<otherValue>&zapxxe;</otherValue>\n"
                        + "<otherValue>&zapxxe;</otherValue>\n"
                        + "\n"
                        + "<otherValue>&zapxxe;</otherValue>\n"
                        + "    </comment>\n"
                        + "</comments>";
        assertThat(payload, is(expectedPayload));
    }

    @Test
    void replaceElementsNested() {
        // Given
        String sampleXmlMessage = getXmlResource("xxescanrule/SampleXml.txt");
        String requestBody = "\n" + "\n" + sampleXmlMessage;
        Matcher tagMatcher = XxeScanRule.tagPattern.matcher(requestBody);
        tagMatcher.find();
        // When
        String payload = XxeScanRule.createTagSpecificLfrPayload(requestBody, tagMatcher);
        // Then
        String expectedPayload =
                XxeScanRule.ATTACK_HEADER
                        + "\n"
                        + "\n"
                        + "<comments>\n"
                        + "    <comment>\n"
                        + "    <text>&zapxxe;</text>\n"
                        + "    </comment>\n"
                        + "\n"
                        + "    <comment>\n"
                        + "    <text>  testTwo  </text>\n"
                        + "    </comment>\n"
                        + "    <comment>\n"
                        + "\n"
                        + "<otherValue>A</otherValue>\n"
                        + "<otherValue>testThree</otherValue>\n"
                        + "<otherValue>C</otherValue>\n"
                        + "\n"
                        + "<otherValue>D</otherValue>\n"
                        + "    </comment>\n"
                        + "</comments>";
        assertThat(payload, is(expectedPayload));
    }

    @Test
    void replaceElementsBase() {
        // Given
        String sampleXmlMessage = getXmlResource("xxescanrule/SampleXml.txt");
        String requestBody = "\n" + "\n" + sampleXmlMessage;
        Matcher tagMatcher = XxeScanRule.tagPattern.matcher(requestBody);
        for (int idx = 1; idx <= 4; idx++) tagMatcher.find();
        // When
        String payload = XxeScanRule.createTagSpecificLfrPayload(requestBody, tagMatcher);
        // Then
        String expectedPayload =
                XxeScanRule.ATTACK_HEADER
                        + "\n"
                        + "\n"
                        + "<comments>\n"
                        + "    <comment>\n"
                        + "    <text>testOne\n"
                        + "    </text>\n"
                        + "    </comment>\n"
                        + "\n"
                        + "    <comment>\n"
                        + "    <text>  testTwo  </text>\n"
                        + "    </comment>\n"
                        + "    <comment>\n"
                        + "\n"
                        + "<otherValue>A</otherValue>\n"
                        + "<otherValue>&zapxxe;</otherValue>\n"
                        + "<otherValue>C</otherValue>\n"
                        + "\n"
                        + "<otherValue>D</otherValue>\n"
                        + "    </comment>\n"
                        + "</comments>";
        assertThat(payload, is(expectedPayload));
    }

    @Test
    void shouldScanOnlyIfRequestContentTypeIsXml() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = this.getHttpMessage("/test");
        msg.getRequestHeader().setHeader("Content-Type", "application/json");
        // The mismatch in request body and content-type is intentional.
        // For any reason if the rule fails to check the Content-Type, then createLfrPayload() will
        // send a message converting the XML body into an attack payload.
        // This may not happen, if the request body is not XML.
        msg.setRequestBody("<?xml version=\"1.0\"?><comment><text>test</text></comment>");
        msg.getRequestHeader().setMethod("POST");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(countMessagesSent, equalTo(0));
    }

    @ParameterizedTest
    @EnumSource(
            value = NanoHTTPD.Response.Status.class,
            names = {"OK", "BAD_REQUEST"})
    void shouldAlertWhenLocalFileReflectedInResponse(NanoHTTPD.Response.Status status)
            throws HttpMalformedHeaderException {
        // Given
        String test = "/test";
        String responseBody = "<foo>root:*:0:0:System Administrator:/var/root:/bin/sh</foo>";
        this.nano.addHandler(createNanoHandler(test, status, responseBody));
        HttpMessage msg = getXmlPostMessage(test);
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        String localFileInclusionAttackPayload =
                MessageFormat.format(XxeScanRule.ATTACK_HEADER, "file:///etc/passwd")
                        + "<comment><text>&zapxxe;</text></comment>";
        List<Alert> alertList =
                alertsRaised.stream()
                        .filter(alert -> alert.getAttack().equals(localFileInclusionAttackPayload))
                        .collect(Collectors.toList());
        assertThat(alertList.size(), equalTo(1));
        Alert alert = alertList.get(0);
        assertThat(alert.getEvidence(), equalTo("root:*:0:0"));
        assertThat(alert.getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alert.getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @ParameterizedTest
    @EnumSource(
            value = NanoHTTPD.Response.Status.class,
            names = {"OK", "BAD_REQUEST"})
    void shouldAlertWhenLocalFileIncludedInResponse(NanoHTTPD.Response.Status status)
            throws HttpMalformedHeaderException {
        // Given
        String test = "/test";
        String responseBody = "[drivers]\n" + "wave=mmdrv.dll";
        this.nano.addHandler(createNanoHandler(test, status, responseBody));
        HttpMessage msg = getXmlPostMessage(test);
        rule.init(msg, parent);
        // When
        // Local File Inclusion Attacks is triggered only when AttackStrength is > Medium
        rule.setAttackStrength(Plugin.AttackStrength.HIGH);
        rule.scan();
        // Then
        String localFileInclusionAttackPayload =
                MessageFormat.format(XxeScanRule.ATTACK_HEADER, "file:///c:/Windows/system.ini")
                        + XxeScanRule.ATTACK_BODY;
        List<Alert> alertList =
                alertsRaised.stream()
                        .filter(alert -> alert.getAttack().equals(localFileInclusionAttackPayload))
                        .collect(Collectors.toList());
        assertThat(alertList.size(), equalTo(1));
        Alert alert = alertList.get(0);
        assertThat(alert.getEvidence(), equalTo("[drivers]"));
        assertThat(alert.getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alert.getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldAlertOnlyIfCertainTagValuesArePresent()
            throws HttpMalformedHeaderException, IOException {
        String validatedXmlMessage = getXmlResource("xxescanrule/SampleXml.txt");
        String sampleRequestBody = "\n" + "<?xml version=\"1.0\"?>\n" + validatedXmlMessage;

        String test = "/test";
        nano.addHandler(new ValidatedResponse(test));
        HttpMessage msg = getXmlPostMessage(test);
        msg.setRequestBody(sampleRequestBody);
        rule.init(msg, parent);
        // When
        rule.setAttackStrength(Plugin.AttackStrength.MEDIUM);
        rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        Alert alert = alertsRaised.get(0);
        String specificElementsReplacedLocalFileInclusionAttackPayload =
                MessageFormat.format(XxeScanRule.ATTACK_HEADER, "file:///etc/passwd")
                        + "\n"
                        + "\n"
                        + "<comments>\n"
                        + "    <comment>\n"
                        + "    <text>testOne\n"
                        + "    </text>\n"
                        + "    </comment>\n"
                        + "\n"
                        + "    <comment>\n"
                        + "    <text>  testTwo  </text>\n"
                        + "    </comment>\n"
                        + "    <comment>\n"
                        + "\n"
                        + "<otherValue>&zapxxe;</otherValue>\n"
                        + "<otherValue>testThree</otherValue>\n"
                        + "<otherValue>C</otherValue>\n"
                        + "\n"
                        + "<otherValue>D</otherValue>\n"
                        + "    </comment>\n"
                        + "</comments>";
        assertThat(
                alert.getAttack(),
                equalTo(specificElementsReplacedLocalFileInclusionAttackPayload));
        assertThat(alert.getEvidence(), equalTo("root:*:0:0"));
        assertThat(alert.getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alert.getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    private NanoServerHandler createNanoHandler(
            String path, NanoHTTPD.Response.IStatus status, String responseBody) {
        return new NanoServerHandler(path) {
            @Override
            protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
                consumeBody(session);
                return newFixedLengthResponse(status, NanoHTTPD.MIME_PLAINTEXT, responseBody);
            }
        };
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(611)));
        assertThat(wasc, is(equalTo(43)));
        assertThat(tags.size(), is(equalTo(3)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(tags.containsKey(CommonAlertTag.OWASP_2017_A04_XXE.getTag()), is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_INPV_07_XMLI.getTag()), is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A03_INJECTION.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A04_XXE.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A04_XXE.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_INPV_07_XMLI.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_INPV_07_XMLI.getValue())));
    }

    private static class ValidatedResponse extends NanoServerHandler {

        public ValidatedResponse(String path) {
            super(path);
        }

        @Override
        protected Response serve(IHTTPSession session) {
            String requestBody = getBody(session);
            if ((requestBody.contains("    <text>testOne\n" + "    </text>\n"))
                    && (requestBody.contains("    <text>  testTwo  </text>\n"))
                    && (requestBody.contains("<otherValue>testThree</otherValue>\n"))) {
                String validResponseBody =
                        "<foo>root:*:0:0:System Administrator:/var/root:/bin/sh</foo>";
                return newFixedLengthResponse(
                        Response.Status.OK, NanoHTTPD.MIME_PLAINTEXT, validResponseBody);
            } else {
                String invalidResponseBody = "The XML received has incorrect tag values";
                return newFixedLengthResponse(
                        Response.Status.BAD_REQUEST, NanoHTTPD.MIME_PLAINTEXT, invalidResponseBody);
            }
        }
    }

    private HttpMessage getXmlPostMessage(String path) throws HttpMalformedHeaderException {
        HttpMessage msg = this.getHttpMessage(path);
        msg.setRequestBody("<?xml version=\"1.0\"?><comment><text>test</text></comment>");
        msg.getRequestHeader().setMethod("POST");
        msg.getRequestHeader().setHeader("Content-Type", "application/xml");
        return msg;
    }

    private static String getXmlResource(String fileName) {
        try {
            String xmlString =
                    FileUtils.readFileToString(
                            new File(XxeScanRuleUnitTest.class.getResource(fileName).getFile()),
                            "UTF-8");
            return xmlString;
        } catch (IOException e) {
            System.err.println("Failed to read file " + fileName);
            throw new RuntimeException(e);
        }
    }
}
