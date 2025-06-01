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
package org.zaproxy.addon.oast.services.boast;

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

class BoastEventUnitTests extends TestUtils {
    private final String id = "czvri2n7gspfwipncso2zedyc4";
    private final String time = "2021-07-30T11:39:49.674610317Z";
    private final String serverId = "5jdpq73adp7edjpprdvig5mr7u";
    private final String receiver = "DNS";
    private final String remoteAddress = "192.0.2.0:12345";
    private final String dump =
            ";; opcode: QUERY, status: NOERROR, id: 36644\n;; flags: cd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; QUESTION SECTION:\n;5jdpq73adp7edjpprdvig5mr7u.odiss.eu.\tIN\t A\n\n;; ADDITIONAL SECTION:\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags: do; udp: 4096\n";
    private final String queryType = "A";
    private final BoastEvent expectedBoastEvent =
            new BoastEvent(id, time, serverId, receiver, remoteAddress, dump, queryType);

    @BeforeEach
    void setUp() throws Exception {
        setUpZap();
        Constant.messages = new I18N(Locale.ROOT);
    }

    @Test
    void shouldCreateValidBoastEventFromJsonObject() {
        // Given
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("id", id);
        jsonObject.put("time", time);
        jsonObject.put("testID", serverId);
        jsonObject.put("receiver", receiver);
        jsonObject.put("remoteAddress", remoteAddress);
        jsonObject.put("dump", dump);
        jsonObject.put("queryType", queryType);

        // When
        BoastEvent boastEvent = new BoastEvent(jsonObject);

        // Then
        assertThat(boastEvent, is(expectedBoastEvent));
    }

    @Test
    void shouldAddDumpToRequestBodyByDefault() throws Exception {
        try (MockedStatic<OastRequest> oastRequest = Mockito.mockStatic(OastRequest.class)) {
            // Given
            BoastEvent boastEvent =
                    new BoastEvent(id, time, serverId, "undefined", remoteAddress, dump, queryType);

            // When
            boastEvent.toOastRequest();

            // Then
            ArgumentCaptor<HttpMessage> httpMessageCaptor =
                    ArgumentCaptor.forClass(HttpMessage.class);
            oastRequest.verify(
                    () ->
                            OastRequest.create(
                                    httpMessageCaptor.capture(), anyString(), anyString()));
            assertThat(httpMessageCaptor.getValue().getRequestBody().toString(), is(dump));
        }
    }

    @Test
    void shouldSeparateHttpMessageDumpHeaderAndBody() throws Exception {
        try (MockedStatic<OastRequest> oastRequest = Mockito.mockStatic(OastRequest.class)) {
            // Given
            String httpDumpHeader =
                    "GET http://localhost:8080/cxcjyaf5wahkidrp2zvhxe6ola HTTP/1.1\r\nUser-Agent: ZAP\r\nContent-type: application/json; charset=utf-8\r\n\r\n";
            String httpDumpBody = "{\"test\": 123}";
            String httpDump = httpDumpHeader + httpDumpBody;
            BoastEvent boastEvent =
                    new BoastEvent(id, time, serverId, "HTTP", remoteAddress, httpDump, queryType);

            // When
            boastEvent.toOastRequest();

            // Then
            ArgumentCaptor<HttpMessage> httpMessageCaptor =
                    ArgumentCaptor.forClass(HttpMessage.class);
            oastRequest.verify(
                    () ->
                            OastRequest.create(
                                    httpMessageCaptor.capture(), anyString(), anyString()));
            HttpMessage capturedMessage = httpMessageCaptor.getValue();
            assertThat(capturedMessage.getRequestHeader().toString(), is(httpDumpHeader));
            assertThat(capturedMessage.getRequestBody().toString(), is(httpDumpBody));
        }
    }

    @Test
    void shouldFindAndAddRequestUriForDnsQueryDumps() throws Exception {
        try (MockedStatic<OastRequest> oastRequest = Mockito.mockStatic(OastRequest.class)) {
            // Given
            String requestUri = "http://example.com/";
            String dnsDump =
                    ";; opcode: QUERY, status: NOERROR, id: 36644\n;; flags: cd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; QUESTION SECTION:\n;"
                            + requestUri
                            + "\tIN\t A\n\n;; ADDITIONAL SECTION:\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags: do; udp: 4096\n";
            BoastEvent boastEvent =
                    new BoastEvent(id, time, serverId, receiver, remoteAddress, dnsDump, queryType);

            // When
            boastEvent.toOastRequest();

            // Then
            ArgumentCaptor<HttpMessage> httpMessageCaptor =
                    ArgumentCaptor.forClass(HttpMessage.class);
            oastRequest.verify(
                    () ->
                            OastRequest.create(
                                    httpMessageCaptor.capture(), anyString(), anyString()));
            assertThat(
                    httpMessageCaptor.getValue().getRequestHeader().getURI().toString(),
                    is(requestUri));
        }
    }

    @Test
    void shouldAddSchemeToUriWithoutSchemeInDnsQueryDumps() throws Exception {
        try (MockedStatic<OastRequest> oastRequest = Mockito.mockStatic(OastRequest.class)) {
            // Given
            String requestUri = "example.com.";
            String dnsDump =
                    ";; opcode: QUERY, status: NOERROR, id: 36644\n;; flags: cd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; QUESTION SECTION:\n;"
                            + requestUri
                            + "\tIN\t A\n\n;; ADDITIONAL SECTION:\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags: do; udp: 4096\n";
            BoastEvent boastEvent =
                    new BoastEvent(id, time, serverId, receiver, remoteAddress, dnsDump, queryType);

            // When
            boastEvent.toOastRequest();

            // Then
            ArgumentCaptor<HttpMessage> httpMessageCaptor =
                    ArgumentCaptor.forClass(HttpMessage.class);
            oastRequest.verify(
                    () ->
                            OastRequest.create(
                                    httpMessageCaptor.capture(), anyString(), anyString()));
            assertThat(
                    httpMessageCaptor.getValue().getRequestHeader().getURI().toString(),
                    is("http://" + requestUri));
        }
    }

    @Test
    void shouldReturnTrueForEqualObjects() {
        // Given
        BoastEvent boastEventOne =
                new BoastEvent(id, time, serverId, receiver, remoteAddress, dump, queryType);
        BoastEvent boastEventTwo =
                new BoastEvent(id, time, serverId, receiver, remoteAddress, dump, queryType);

        // Then
        assertThat(boastEventOne.equals(boastEventTwo), is(true));
    }

    @Test
    void shouldReturnSameHashCodeForEqualObjects() {
        // Given
        BoastEvent boastEventOne =
                new BoastEvent(id, time, serverId, receiver, remoteAddress, dump, queryType);
        BoastEvent boastEventTwo =
                new BoastEvent(id, time, serverId, receiver, remoteAddress, dump, queryType);

        // Then
        assertThat(boastEventOne.hashCode() == boastEventTwo.hashCode(), is(true));
    }
}
