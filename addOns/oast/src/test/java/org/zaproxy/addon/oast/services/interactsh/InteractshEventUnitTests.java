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
package org.zaproxy.addon.oast.services.interactsh;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.anyString;

import java.util.Locale;
import net.sf.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.oast.OastRequest;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.I18N;

class InteractshEventUnitTests extends TestUtils {
    private final String protocol = "dns";
    private final String uniqueId = "c4sr5v02eke4m3ndgl90crh5gooyyyyyy";
    private final String fullId = "c4sr5v02eke4m3ndgl90crh5gooyyyyyy";
    private final String rawRequest =
            ";; opcode: QUERY, status: NOERROR, id: 36315\n;; flags:; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; QUESTION SECTION:\n;c4sr5v02eke4m3ndgl90crh5gooyyyyyy.interact.sh.\tIN\t A\n\n;; ADDITIONAL SECTION:\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags: do; udp: 1452\n";
    private final String rawResponse =
            ";; opcode: QUERY, status: NOERROR, id: 36315\n;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 2, ADDITIONAL: 2\n\n;; QUESTION SECTION:\n;c4sr5v02eke4m3ndgl90crh5gooyyyyyy.interact.sh.\tIN\t A\n\n;; ANSWER SECTION:\nc4sr5v02eke4m3ndgl90crh5gooyyyyyy.interact.sh.\t3600\tIN\tA\t46.101.25.250\n\n;; AUTHORITY SECTION:\nc4sr5v02eke4m3ndgl90crh5gooyyyyyy.interact.sh.\t3600\tIN\tNS\tns1.interact.sh.\nc4sr5v02eke4m3ndgl90crh5gooyyyyyy.interact.sh.\t3600\tIN\tNS\tns2.interact.sh.\n\n;; ADDITIONAL SECTION:\nns1.interact.sh.\t3600\tIN\tA\t46.101.25.250\nns2.interact.sh.\t3600\tIN\tA\t46.101.25.250\n";
    private final String remoteAddress = "192.0.2.0:12345";
    private final String timestamp = "2021-07-30T11:39:49.674610317Z";
    private final String queryType = "A";
    private final InteractshEvent expectedEvent =
            new InteractshEvent(
                    protocol,
                    uniqueId,
                    fullId,
                    rawRequest,
                    rawResponse,
                    remoteAddress,
                    timestamp,
                    queryType,
                    "");

    @BeforeEach
    void setUp() throws Exception {
        setUpZap();
        Constant.messages = new I18N(Locale.ROOT);
    }

    @Test
    void shouldCreateValidBoastEventFromJsonObject() {
        // Given
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("protocol", protocol);
        jsonObject.put("unique-id", uniqueId);
        jsonObject.put("full-id", fullId);
        jsonObject.put("raw-request", rawRequest);
        jsonObject.put("raw-response", rawResponse);
        jsonObject.put("remote-address", remoteAddress);
        jsonObject.put("timestamp", timestamp);
        jsonObject.put("q-type", queryType);
        jsonObject.put("smtp-from", "");

        // When
        InteractshEvent event = new InteractshEvent(jsonObject);

        // Then
        assertThat(event, is(expectedEvent));
    }

    @Test
    void shouldSeparateHttpMessageHeaderAndBody() throws Exception {
        try (MockedStatic<OastRequest> oastRequest = Mockito.mockStatic(OastRequest.class)) {
            // Given
            String reqHeader =
                    "GET https://c4sr5v02eke4m3ndgl90crh5gooyyyyyy.interact.sh HTTP/1.1\r\nUser-Agent: ZAP\r\nContent-type: application/json; charset=utf-8\r\n\r\n";
            String reqBody = "{\"test\": 123}";
            String request = reqHeader + reqBody;
            String resHeader =
                    "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n";
            String resBody = "<html><head></head><body>abc</body></html>";
            String response = resHeader + resBody;
            InteractshEvent event =
                    new InteractshEvent(
                            "http",
                            uniqueId,
                            fullId,
                            request,
                            response,
                            remoteAddress,
                            timestamp,
                            queryType,
                            "");

            // When
            event.toOastRequest();

            // Then
            ArgumentCaptor<HttpMessage> httpMessageCaptor =
                    ArgumentCaptor.forClass(HttpMessage.class);
            oastRequest.verify(
                    () ->
                            OastRequest.create(
                                    httpMessageCaptor.capture(), anyString(), anyString()));
            HttpMessage capturedMessage = httpMessageCaptor.getValue();
            assertThat(capturedMessage.getRequestHeader().toString(), is(reqHeader));
            assertThat(capturedMessage.getRequestBody().toString(), is(reqBody));
            assertThat(capturedMessage.getResponseHeader().toString(), is(resHeader));
            assertThat(capturedMessage.getResponseBody().toString(), is(resBody));
        }
    }

    @Test
    void shouldAddEmailToHeaderForSmtpMessages() throws Exception {
        try (MockedStatic<OastRequest> oastRequest = Mockito.mockStatic(OastRequest.class)) {
            // Given
            String email = "example@zaproxy.org";
            InteractshEvent event =
                    new InteractshEvent(
                            "smtp",
                            uniqueId,
                            fullId,
                            "",
                            "",
                            remoteAddress,
                            timestamp,
                            queryType,
                            email);

            // When
            event.toOastRequest();

            // Then
            ArgumentCaptor<HttpMessage> httpMessageCaptor =
                    ArgumentCaptor.forClass(HttpMessage.class);
            oastRequest.verify(
                    () ->
                            OastRequest.create(
                                    httpMessageCaptor.capture(), anyString(), anyString()));
            HttpMessage capturedMessage = httpMessageCaptor.getValue();
            assertThat(
                    capturedMessage.getRequestHeader().getHeader(InteractshEvent.EMAIL_FROM_HEADER),
                    is(email));
        }
    }

    @Test
    void shouldReturnTrueForEqualObjects() {
        // Given
        String email = "example@zaproxy.org";
        InteractshEvent eventOne =
                new InteractshEvent(
                        protocol,
                        uniqueId,
                        fullId,
                        rawRequest,
                        rawResponse,
                        remoteAddress,
                        timestamp,
                        queryType,
                        email);
        InteractshEvent eventTwo =
                new InteractshEvent(
                        protocol,
                        uniqueId,
                        fullId,
                        rawRequest,
                        rawResponse,
                        remoteAddress,
                        timestamp,
                        queryType,
                        email);

        // Then
        assertThat(eventOne.equals(eventTwo), is(true));
    }

    @Test
    void shouldReturnSameHashCodeForEqualObjects() {
        // Given
        String email = "example@zaproxy.org";
        InteractshEvent eventOne =
                new InteractshEvent(
                        protocol,
                        uniqueId,
                        fullId,
                        rawRequest,
                        rawResponse,
                        remoteAddress,
                        timestamp,
                        queryType,
                        email);
        InteractshEvent eventTwo =
                new InteractshEvent(
                        protocol,
                        uniqueId,
                        fullId,
                        rawRequest,
                        rawResponse,
                        remoteAddress,
                        timestamp,
                        queryType,
                        email);

        // Then
        assertThat(eventOne.hashCode() == eventTwo.hashCode(), is(true));
    }
}
