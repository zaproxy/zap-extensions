/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.llm.ui;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;

class LlmAppendHttpMessageMenuUnitTest {

    @Test
    void shouldBuildStructuredHttpPayloadWithRequestAndResponse() throws Exception {
        // Given
        HttpMessage message = createHttpMessage();

        // When
        Map<String, Object> payload =
                LlmAppendHttpMessageMenu.buildStructuredPayload(message, true, true);

        // Then
        assertThat(payload.get("type"), is("http_message"));
        assertThat(payload.get("uri"), is("http://example.com/test"));

        Map<String, Object> request = getMap(payload, "request");
        assertThat(request.get("header").toString(), containsString("POST"));
        assertThat(request.get("body"), is("req-body"));

        Map<String, Object> response = getMap(payload, "response");
        assertThat(response.get("header").toString(), containsString("HTTP/1.1 200 OK"));
        assertThat(response.get("body"), is("resp-body"));
    }

    @Test
    void shouldExcludeRequestAndResponseWhenDisabled() throws Exception {
        // Given
        HttpMessage message = createHttpMessage();

        // When
        Map<String, Object> payload =
                LlmAppendHttpMessageMenu.buildStructuredPayload(message, false, false);

        // Then
        assertThat(payload.get("type"), is("http_message"));
        assertThat(payload.get("uri"), is("http://example.com/test"));
        assertThat(payload, not(hasKey("request")));
        assertThat(payload, not(hasKey("response")));
    }

    private static HttpMessage createHttpMessage() throws Exception {
        HttpMessage message = new HttpMessage();
        HttpRequestHeader requestHeader = new HttpRequestHeader();
        requestHeader.setURI(new URI("http://example.com/test", false));
        requestHeader.setMethod(HttpRequestHeader.POST);
        message.setRequestHeader(requestHeader);
        message.getRequestBody().setBody("req-body");

        HttpResponseHeader responseHeader =
                new HttpResponseHeader("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n");
        message.setResponseHeader(responseHeader);
        message.getResponseBody().setBody("resp-body");

        return message;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> getMap(Map<String, Object> payload, String key) {
        return (Map<String, Object>) payload.get(key);
    }
}
