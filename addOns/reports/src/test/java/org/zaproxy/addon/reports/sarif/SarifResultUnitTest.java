/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.reports.sarif;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.zaproxy.addon.reports.sarif.TestAlertBuilder.newAlertBuilder;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.reports.sarif.SarifResult.SarifArtifactLocation;
import org.zaproxy.addon.reports.sarif.SarifResult.SarifBody;
import org.zaproxy.addon.reports.sarif.SarifResult.SarifRegion;
import org.zaproxy.addon.reports.sarif.SarifResult.SarifResultLocation;

class SarifResultUnitTest {

    private static final String PSEUDO_BASE64_ENCODED_CONTENT = "somethingBase64Encoded";
    private static final String A_SIMPLE_BODY = "the-body";

    SarifBase64Encoder encoder;
    SarifBinaryContentDetector binaryContentDetector;

    @BeforeEach
    void beforeEach() {
        encoder = mock(SarifBase64Encoder.class);
        binaryContentDetector = mock(SarifBinaryContentDetector.class);
    }

    @DisplayName(
            "A region with incorrect start line set, method getValidStartLineOrFallback returns 1 as fallback")
    @ParameterizedTest
    @ValueSource(longs = {0, -1, -100})
    void sarifRegionGetValidStartLineOrFallbackForInvalidStartLine(long value) {

        /* prepare */
        SarifRegion region = new SarifRegion();
        region.startLine = value;

        /* test */
        assertEquals(1, region.getValidStartLineOrFallback());

        // test other getters as well:
        assertTrue(region.isStartLineInvalid());
        assertEquals(value, region.getStartLine());
    }

    @DisplayName(
            "For a region with correct start line set, method getValidStartLineOrFallback returns start line")
    @ParameterizedTest
    @ValueSource(longs = {1, 2, 4711})
    void sarifRegionGetValidStartLineOrFallbackForValidStartLine(long value) {

        /* prepare */
        SarifRegion region = new SarifRegion();
        region.startLine = value;

        /* test */
        assertEquals(value, region.getValidStartLineOrFallback());

        // test other getters as well:
        assertFalse(region.isStartLineInvalid());
        assertEquals(value, region.getStartLine());
    }

    @DisplayName("A high risk alert will be converted to corresponding sarif result")
    @Test
    void aHighRiskAlertWillBeConvertedToCorrespondingSarifResult() {

        /* prepare */
        Alert alert =
                newAlertBuilder()
                        .setRisk(Alert.RISK_HIGH)
                        .setUriString("https://example.com/highrisk")
                        .setDescription("description1")
                        .setEvidence("evidence1")
                        .setAttack("attack1")
                        .setName("name1")
                        .setPluginId(12345)
                        .build();

        /* execute */
        SarifResult result = SarifResult.builder().setAlert(alert).build();

        /* test */
        assertEquals(SarifLevel.ERROR, result.getLevel());

        assertEquals(1, result.getLocations().size());
        SarifResultLocation firstLocation = result.getLocations().iterator().next();
        assertEquals("attack1", firstLocation.getProperties().getAttack());
        assertEquals(
                "evidence1",
                firstLocation.getPhysicalLocation().getRegion().getSnippet().getText());
        SarifArtifactLocation artifactLocation =
                firstLocation.getPhysicalLocation().getArtifactLocation();

        assertEquals("description1", result.getMessage().getText());
        assertEquals("12345", result.getRuleId());
        assertEquals("https://example.com/highrisk", artifactLocation.getUri());
    }

    @DisplayName(
            "When content detector decides it is binary - SARIF Webresponse body has no text, but binary with base64 encoded body bytes")
    @Test
    void webResponseBinary() {

        /* prepare */
        Alert alert =
                newAlertBuilder()
                        .setResponseBody(A_SIMPLE_BODY)
                        .setResponseHeader("HTTP/1.1 200")
                        .build();

        when(binaryContentDetector.isBinaryContent(eq(alert.getMessage().getResponseHeader())))
                .thenReturn(true);
        when(encoder.encodeBytesToBase64(any())).thenReturn(PSEUDO_BASE64_ENCODED_CONTENT);

        /* execute */
        SarifResult result =
                SarifResult.builder()
                        .setAlert(alert)
                        .setBase64Encoder(encoder)
                        .setBinaryContentDetector(binaryContentDetector)
                        .build();

        /* test */
        SarifBody body = result.getWebResponse().getBody();
        assertEquals(null, body.getText());
        assertEquals(PSEUDO_BASE64_ENCODED_CONTENT, body.getBinary());
    }

    @DisplayName(
            "When content detector decides its NOT binary - SARIF Webresponse body has plain text")
    @Test
    void webResponseNotBinary() {

        /* prepare */
        Alert alert =
                newAlertBuilder()
                        .setResponseBody(A_SIMPLE_BODY)
                        .setResponseHeader("HTTP/1.1 200")
                        .build();

        when(binaryContentDetector.isBinaryContent(eq(alert.getMessage().getResponseHeader())))
                .thenReturn(false);
        when(encoder.encodeBytesToBase64(any())).thenReturn(PSEUDO_BASE64_ENCODED_CONTENT);

        /* execute */
        SarifResult result =
                SarifResult.builder()
                        .setAlert(alert)
                        .setBase64Encoder(encoder)
                        .setBinaryContentDetector(binaryContentDetector)
                        .build();

        /* test */
        SarifBody body = result.getWebResponse().getBody();
        assertEquals(null, body.getBinary());
        assertEquals(A_SIMPLE_BODY, body.getText());
    }

    @DisplayName(
            "When content detector decides it is binary - SARIF Webrequest body has no text, but binary with base64 encoded body bytes")
    @Test
    void webRequestBinary() {

        /* prepare */
        Alert alert =
                newAlertBuilder()
                        .setRequestBody(A_SIMPLE_BODY)
                        .setRequestHeader("GET https://127.0.0.1:8080 HTTP/1.1")
                        .build();

        when(binaryContentDetector.isBinaryContent(eq(alert.getMessage().getRequestHeader())))
                .thenReturn(true);
        when(encoder.encodeBytesToBase64(any())).thenReturn(PSEUDO_BASE64_ENCODED_CONTENT);

        /* execute */
        SarifResult result =
                SarifResult.builder()
                        .setAlert(alert)
                        .setBase64Encoder(encoder)
                        .setBinaryContentDetector(binaryContentDetector)
                        .build();

        /* test */
        SarifBody body = result.getWebRequest().getBody();
        assertEquals(null, body.getText());
        assertEquals(PSEUDO_BASE64_ENCODED_CONTENT, body.getBinary());
    }

    @DisplayName(
            "When content detector decides it is NOT binary - SARIF Webrequest body has plain text")
    @Test
    void webRequestNotBinary() {

        /* prepare */
        Alert alert =
                newAlertBuilder()
                        .setRequestBody(A_SIMPLE_BODY)
                        .setRequestHeader("GET https://127.0.0.1:8080 HTTP/1.1")
                        .build();

        when(binaryContentDetector.isBinaryContent(eq(alert.getMessage().getRequestHeader())))
                .thenReturn(false);
        when(encoder.encodeBytesToBase64(any())).thenReturn(PSEUDO_BASE64_ENCODED_CONTENT);

        /* execute */
        SarifResult result =
                SarifResult.builder()
                        .setAlert(alert)
                        .setBase64Encoder(encoder)
                        .setBinaryContentDetector(binaryContentDetector)
                        .build();

        /* test */
        SarifBody body = result.getWebRequest().getBody();
        assertEquals(null, body.getBinary());
        assertEquals(A_SIMPLE_BODY, body.getText());
    }

    @Test
    void headerContainingBasicAuthAuthorizationInfoWillBeHiddenInReport() {

        /* prepare */
        Alert alert =
                newAlertBuilder()
                        .setRequestBody(A_SIMPLE_BODY)
                        .setRequestHeader(
                                "GET https://127.0.0.1:8080 HTTP/1.1\nAccept-Language: en-us,en;q=0.5\nAuthorization: Basic dXNlcjpwYXNzd29yZA==")
                        .build();

        when(binaryContentDetector.isBinaryContent(eq(alert.getMessage().getRequestHeader())))
                .thenReturn(false);
        when(encoder.encodeBytesToBase64(any())).thenReturn(PSEUDO_BASE64_ENCODED_CONTENT);

        /* execute */
        SarifResult result =
                SarifResult.builder()
                        .setAlert(alert)
                        .setBase64Encoder(encoder)
                        .setBinaryContentDetector(binaryContentDetector)
                        .build();

        /* test */
        Map<String, String> headers = result.getWebRequest().getHeaders();
        assertEquals("en-us,en;q=0.5", headers.get("Accept-Language"));
        assertEquals(
                SarifHeaderCredentialHider.CREDENTIAL_REPLACEMENT_ASTERISKS,
                headers.get("Authorization"));
    }

    @ParameterizedTest(name = "A list containing rules {0} is sorted to {1}")
    @CsvSource({
        "1:ERROR-2:ERROR-3:ERROR,1-2-3",
        "1:ERROR-3:ERROR-2:ERROR,1-2-3",
        "40023:ERROR-40012:ERROR-50012:ERROR-1000:ERROR-3:ERROR,3-1000-40012-40023-50012",
        "40023:NOTE-40012:ERROR-50012:ERROR-1000:ERROR-3:ERROR,3-1000-40012-50012-40023",
        "40023:NOTE-40012:ERROR-50012:ERROR-1000:WARNING-3:NOTE,40012-50012-1000-3-40023",
    })
    void sortingDoneByLevelAndPluginId(
            String creationOrderString, String expectedSortedOrderString) {

        /* prepare */
        OrderedCSVTestData[] creationOrder =
                extractOrderAndAlertRiskFromString(creationOrderString);
        OrderedCSVTestData[] expectedSortedOrder =
                extractOrderAndAlertRiskFromString(expectedSortedOrderString);

        // add in wanted, initial ordering
        List<SarifResult> arrayList = new ArrayList<>();
        for (OrderedCSVTestData creationOrderData : creationOrder) {
            Alert alert = createAlertWithPluginId(creationOrderData);
            SarifResult sarifResult = SarifResult.builder().setAlert(alert).build();
            arrayList.add(sarifResult);
        }

        /* execute */
        Collections.sort(arrayList);

        /* test */
        Iterator<SarifResult> it = arrayList.iterator();
        for (OrderedCSVTestData expectedOrderData : expectedSortedOrder) {
            SarifResult found = it.next();
            assertEquals("" + expectedOrderData.pluginId, found.getRuleId());
        }
    }

    private Alert createAlertWithPluginId(OrderedCSVTestData creationOrderData) {
        Alert alert = mock(Alert.class);
        when(alert.getPluginId()).thenReturn(creationOrderData.pluginId);
        when(alert.getRisk()).thenReturn(creationOrderData.level.getAlertRisk());
        HttpMessage message = new HttpMessage(); // mock(HttpMessage.class);
        when(alert.getMessage()).thenReturn(message);
        return alert;
    }

    private class OrderedCSVTestData {
        int pluginId;
        SarifLevel level;
    }

    private OrderedCSVTestData[] extractOrderAndAlertRiskFromString(String order) {
        String[] splitted = order.split("-");
        OrderedCSVTestData[] result = new OrderedCSVTestData[splitted.length];
        for (int i = 0; i < result.length; i++) {
            String split = splitted[i];
            String[] pair = split.split(":");
            result[i] = new OrderedCSVTestData();
            result[i].pluginId = Integer.parseInt(pair[0]);

            if (pair.length > 1) {
                // sarif level defined
                String sarifLevelName = pair[1];
                result[i].level = SarifLevel.valueOf(sarifLevelName);
            }
        }
        return result;
    }
}
