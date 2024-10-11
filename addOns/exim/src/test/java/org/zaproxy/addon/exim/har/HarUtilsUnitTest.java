/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.exim.har;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import de.sstoehr.harreader.model.HarEntry;
import java.nio.charset.StandardCharsets;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link HarUtils}. */
class HarUtilsUnitTest extends TestUtils {

    @BeforeEach
    void setUp() {
        Model model = mock(Model.class, withSettings().strictness(Strictness.LENIENT));
        Model.setSingletonForTesting(model);
        Session session = mock(Session.class);
        given(model.getSession()).willReturn(session);
    }

    @Test
    void shouldCreateHttpMessageFromHarRequest() throws Exception {
        // Given
        var request =
                "{"
                        + "  \"request\" : {\n"
                        + "    \"method\" : \"POST\",\n"
                        + "    \"url\" : \"http://www.example.org/path?a=b&c=d\",\n"
                        + "    \"httpVersion\" : \"HTTP/1.1\",\n"
                        + "    \"cookies\" : [ ],\n"
                        + "    \"headers\" : [ {\n"
                        + "      \"name\" : \"content-type\",\n"
                        + "      \"value\" : \"application/json\"\n"
                        + "    }, {\n"
                        + "      \"name\" : \"content-length\",\n"
                        + "      \"value\" : \"16\"\n"
                        + "    }, {\n"
                        + "      \"name\" : \"host\",\n"
                        + "      \"value\" : \"www.example.org\"\n"
                        + "    } ],\n"
                        + "    \"queryString\" : [ {\n"
                        + "      \"name\" : \"a\",\n"
                        + "      \"value\" : \"b\"\n"
                        + "    }, {\n"
                        + "      \"name\" : \"c\",\n"
                        + "      \"value\" : \"d\"\n"
                        + "    } ],\n"
                        + "    \"postData\" : {\n"
                        + "      \"mimeType\" : \"application/json\",\n"
                        + "      \"params\" : [ ],\n"
                        + "      \"text\" : \"{\\\"a\\\":\\\"1\\\", \\\"b\\\":2}\"\n"
                        + "    },\n"
                        + "    \"headersSize\" : 128,\n"
                        + "    \"bodySize\" : 16\n"
                        + "  }\n"
                        + "}";
        // When
        HttpMessage message = HarUtils.createHttpMessage(request);
        // Then
        assertThat(
                message.getRequestHeader().toString(),
                is(
                        equalTo(
                                "POST http://www.example.org/path?a=b&c=d HTTP/1.1\r\n"
                                        + "content-type: application/json\r\n"
                                        + "content-length: 16\r\n"
                                        + "host: www.example.org\r\n\r\n")));
        assertThat(message.getRequestBody().toString(), is(equalTo("{\"a\":\"1\", \"b\":2}")));
    }

    @Test
    void shouldCreateHarEntryWithMessageNote() throws Exception {
        // Given
        String note = "Message Note";
        HttpMessage message = createHttpMessage();
        message.setNote(note);
        // When
        HarEntry entry = HarUtils.createHarEntry(message);
        // Then
        assertThat(
                entry.getAdditional().get(HarUtils.MESSAGE_NOTE_CUSTOM_FIELD), is(equalTo(note)));
    }

    private static HttpMessage createHttpMessage()
            throws HttpMalformedHeaderException, URIException {
        return new HttpMessage(new URI("http://example.com", true));
    }

    @Test
    void shouldCreateHarEntryWithIdTypeAndMessageNote() throws Exception {
        // Given
        int id = 1;
        int type = 2;
        String note = "Message Note";
        HttpMessage message = createHttpMessage();
        message.setNote(note);
        // When
        HarEntry entry = HarUtils.createHarEntry(id, type, message);
        // Then
        assertThat(entry.getAdditional().get(HarUtils.MESSAGE_ID_CUSTOM_FIELD), is(equalTo(id)));
        assertThat(
                entry.getAdditional().get(HarUtils.MESSAGE_TYPE_CUSTOM_FIELD), is(equalTo(type)));
        assertThat(
                entry.getAdditional().get(HarUtils.MESSAGE_NOTE_CUSTOM_FIELD), is(equalTo(note)));
    }

    @Test
    void shouldCreateJsonAsBytesFromHarLog() throws Exception {
        // Given
        var log = HarUtils.createZapHarLog();
        log.getEntries().add(HarUtils.createHarEntry(1, 2, createHttpMessage()));
        // When
        byte[] bytes = HarUtils.toJsonAsBytes(log);
        // Then
        assertThat(
                new String(bytes, StandardCharsets.UTF_8),
                is(
                        equalTo(
                                "{\n"
                                        + "  \"log\" : {\n"
                                        + "    \"version\" : \"1.2\",\n"
                                        + "    \"creator\" : {\n"
                                        + "      \"name\" : \"ZAP\",\n"
                                        + "      \"version\" : \"Dev Build\"\n"
                                        + "    },\n"
                                        + "    \"browser\" : { },\n"
                                        + "    \"pages\" : [ ],\n"
                                        + "    \"entries\" : [ {\n"
                                        + "      \"startedDateTime\" : \"1970-01-01T00:00:00.000+00:00\",\n"
                                        + "      \"time\" : 0,\n"
                                        + "      \"request\" : {\n"
                                        + "        \"method\" : \"GET\",\n"
                                        + "        \"url\" : \"http://example.com\",\n"
                                        + "        \"httpVersion\" : \"HTTP/1.1\",\n"
                                        + "        \"cookies\" : [ ],\n"
                                        + "        \"headers\" : [ {\n"
                                        + "          \"name\" : \"host\",\n"
                                        + "          \"value\" : \"example.com\"\n"
                                        + "        }, {\n"
                                        + "          \"name\" : \"user-agent\",\n"
                                        + "          \"value\" : \"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0\"\n"
                                        + "        }, {\n"
                                        + "          \"name\" : \"pragma\",\n"
                                        + "          \"value\" : \"no-cache\"\n"
                                        + "        }, {\n"
                                        + "          \"name\" : \"cache-control\",\n"
                                        + "          \"value\" : \"no-cache\"\n"
                                        + "        } ],\n"
                                        + "        \"queryString\" : [ ],\n"
                                        + "        \"postData\" : {\n"
                                        + "          \"mimeType\" : \"\",\n"
                                        + "          \"params\" : [ ],\n"
                                        + "          \"text\" : \"\"\n"
                                        + "        },\n"
                                        + "        \"headersSize\" : 191,\n"
                                        + "        \"bodySize\" : 0\n"
                                        + "      },\n"
                                        + "      \"response\" : {\n"
                                        + "        \"status\" : 0,\n"
                                        + "        \"statusText\" : \"\",\n"
                                        + "        \"httpVersion\" : \"HTTP/1.0\",\n"
                                        + "        \"cookies\" : [ ],\n"
                                        + "        \"headers\" : [ ],\n"
                                        + "        \"content\" : {\n"
                                        + "          \"size\" : 0,\n"
                                        + "          \"compression\" : 0,\n"
                                        + "          \"mimeType\" : \"\"\n"
                                        + "        },\n"
                                        + "        \"redirectURL\" : \"\",\n"
                                        + "        \"headersSize\" : 14,\n"
                                        + "        \"bodySize\" : 0\n"
                                        + "      },\n"
                                        + "      \"cache\" : { },\n"
                                        + "      \"timings\" : {\n"
                                        + "        \"blocked\" : -1,\n"
                                        + "        \"dns\" : -1,\n"
                                        + "        \"connect\" : -1,\n"
                                        + "        \"send\" : 0,\n"
                                        + "        \"wait\" : 0,\n"
                                        + "        \"receive\" : 0,\n"
                                        + "        \"ssl\" : -1\n"
                                        + "      },\n"
                                        + "      \"_zapMessageId\" : 1,\n"
                                        + "      \"_zapMessageNote\" : \"\",\n"
                                        + "      \"_zapMessageType\" : 2\n"
                                        + "    } ]\n"
                                        + "  }\n"
                                        + "}")));
    }
}
