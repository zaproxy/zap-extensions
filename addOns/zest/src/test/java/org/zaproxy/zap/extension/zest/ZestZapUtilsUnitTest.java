/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.zest;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URI;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.utils.ZapXmlConfiguration;
import org.zaproxy.zest.core.v1.ZestRequest;
import org.zaproxy.zest.core.v1.ZestResponse;

/** Unit test for {@link ZestZapUtils}. */
class ZestZapUtilsUnitTest {

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldThrowIfNoUriWhenConvertingHttpMessageToZestRequest(boolean replaceTokens) {
        // Given
        HttpMessage httpMessage = new HttpMessage();
        // When / Then
        HttpMalformedHeaderException e =
                assertThrows(
                        HttpMalformedHeaderException.class,
                        () ->
                                ZestZapUtils.toZestRequest(
                                        httpMessage, replaceTokens, false, createZestParam()));
        assertThat(e.getMessage(), is(equalTo("The request header does not have a URI.")));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldIncludeRquestMethodWhenConvertingHttpMessageToZestRequest(boolean replaceTokens)
            throws Exception {
        // Given
        HttpMessage httpMessage = createRequest("");
        // When
        ZestRequest zestRequest =
                ZestZapUtils.toZestRequest(httpMessage, replaceTokens, false, createZestParam());
        // Then
        assertThat(zestRequest.getMethod(), is(equalTo("GET")));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldIncludeTimeStampWhenConvertingHttpMessageToZestRequest(boolean replaceTokens)
            throws Exception {
        // Given
        HttpMessage httpMessage = createRequest("");
        httpMessage.setTimeSentMillis(42L);
        // When
        ZestRequest zestRequest =
                ZestZapUtils.toZestRequest(httpMessage, replaceTokens, false, createZestParam());
        // Then
        assertThat(zestRequest.getTimestamp(), is(equalTo(42L)));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldNotFollowRedirectsWhenConvertingHttpMessageToZestRequest(boolean replaceTokens)
            throws Exception {
        // Given
        HttpMessage httpMessage = createRequest("");
        // When
        ZestRequest zestRequest =
                ZestZapUtils.toZestRequest(httpMessage, replaceTokens, false, createZestParam());
        // Then
        assertThat(zestRequest.isFollowRedirects(), is(equalTo(false)));
    }

    @Test
    void shouldKeepAllHeadersIfIncludingAllWhenConvertingHttpMessageToZestRequest()
            throws Exception {
        // Given
        boolean includeAllHeaders = true;
        ZestParam zestParam = createZestParam();
        zestParam.setIgnoredHeaders(Arrays.asList("B"));
        String headers = "A: 1\r\nB: 2\r\nHost: example.com\r\n";
        HttpMessage httpMessage = createRequest(headers);
        // When
        ZestRequest zestRequest =
                ZestZapUtils.toZestRequest(httpMessage, false, includeAllHeaders, zestParam);
        // Then
        assertThat(zestRequest.getHeaders(), is(equalTo(headers)));
    }

    @Test
    void shouldRemoveIgnoredHeadersIfNotIncludingAllWhenConvertingHttpMessageToZestRequest()
            throws Exception {
        // Given
        boolean includeAllHeaders = false;
        ZestParam zestParam = createZestParam();
        zestParam.setIgnoredHeaders(Arrays.asList("B"));
        HttpMessage httpMessage = createRequest("A: 1\r\nB: 2\r\nHost: example.com\r\n");
        // When
        ZestRequest zestRequest =
                ZestZapUtils.toZestRequest(httpMessage, false, includeAllHeaders, zestParam);
        // Then
        assertThat(zestRequest.getHeaders(), is(equalTo("A: 1\r\nHost: example.com\r\n")));
    }

    @Test
    void shouldIncludeResponseIfEnabledWhenConvertingHttpMessageToZestRequest() throws Exception {
        // Given
        ZestParam zestParam = createZestParam();
        zestParam.setIncludeResponses(true);
        HttpMessage httpMessage = createRequest("A: 1\r\nB: 2\r\nHost: example.com\r\n");
        var response = "HTTP/1.1 200 OK\r\nC: 3\r\n\r\n";
        httpMessage.setResponseHeader(response);
        // When
        ZestRequest zestRequest = ZestZapUtils.toZestRequest(httpMessage, false, false, zestParam);
        // Then
        assertThat(zestRequest.getResponse(), is(not(nullValue())));
        assertThat(zestRequest.getResponse().getHeaders(), is(equalTo(response)));
    }

    @Test
    void shouldNotIncludeResponseIfNotEnabledWhenConvertingHttpMessageToZestRequest()
            throws Exception {
        // Given
        ZestParam zestParam = createZestParam();
        zestParam.setIncludeResponses(false);
        HttpMessage httpMessage = createRequest("A: 1\r\nB: 2\r\nHost: example.com\r\n");
        httpMessage.setResponseHeader("HTTP/1.1 200 OK");
        // When
        ZestRequest zestRequest = ZestZapUtils.toZestRequest(httpMessage, false, false, zestParam);
        // Then
        assertThat(zestRequest.getResponse(), is(nullValue()));
    }

    @Test
    void shouldCreateStdHttpMessage() throws Exception {
        // Given
        String urlStr = "https://www.example.com";
        ZestRequest req = new ZestRequest();
        req.setUrl(new URI(urlStr).toURL());
        req.setMethod("GET");
        req.setHeaders("example-req-header: example-value");
        ZestResponse resp =
                new ZestResponse(
                        new URI(urlStr).toURL(),
                        "HTTP/1.1 200 OK\r\nexample-resp-header: example-value",
                        "The body",
                        200,
                        1234);

        // When
        HttpMessage msg = ZestZapUtils.toHttpMessage(req, resp);

        // Then
        assertThat(msg, is(not(nullValue())));
        assertThat(msg.getRequestHeader(), is(not(nullValue())));
        assertThat(msg.getRequestHeader().getURI().toString(), is(urlStr));
        assertThat(msg.getRequestHeader().getHeaders().size(), is(2));
        assertThat(msg.getRequestHeader().getHeaders().get(0).getName(), is("example-req-header"));
        assertThat(msg.getRequestHeader().getHeaders().get(0).getValue(), is("example-value"));
        assertThat(msg.getRequestHeader().getHeaders().get(1).getName(), is("content-length"));
        assertThat(msg.getRequestHeader().getHeaders().get(1).getValue(), is("0"));
        assertThat(msg.getRequestBody(), is(not(nullValue())));
        assertThat(msg.getRequestBody().toString().length(), is(0));
        assertThat(msg.getResponseHeader(), is(not(nullValue())));
        assertThat(msg.getTimeElapsedMillis(), is(1234));
        assertThat(msg.getResponseHeader().getStatusCode(), is(200));
        assertThat(msg.getResponseHeader().getHeaders().size(), is(1));
        assertThat(
                msg.getResponseHeader().getHeaders().get(0).getName(), is("example-resp-header"));
        assertThat(msg.getResponseHeader().getHeaders().get(0).getValue(), is("example-value"));
        assertThat(msg.getResponseBody(), is(not(nullValue())));
        assertThat(msg.getResponseBody().toString(), is("The body"));
    }

    @Test
    void shouldCreateHttpMessageWithTokenInUrl() throws Exception {
        // Given
        String urlStr = "https://www.example.com";
        ZestRequest req = new ZestRequest();
        req.setUrlToken(urlStr + "/{{token}}");
        req.setMethod("GET");
        req.setHeaders("example-req-header: example-value");
        ZestResponse resp =
                new ZestResponse(
                        new URI(urlStr).toURL(),
                        "HTTP/1.1 200 OK\r\nexample-resp-header: example-value",
                        "The body",
                        200,
                        1234);

        // When
        HttpMessage msg = ZestZapUtils.toHttpMessage(req, resp);

        // Then
        assertThat(msg, is(not(nullValue())));
        assertThat(msg.getRequestHeader(), is(not(nullValue())));
        assertThat(msg.getRequestHeader().getURI().toString(), is(urlStr + "/%7B%7Btoken%7D%7D"));
        assertThat(msg.getRequestHeader().getHeaders().size(), is(2));
        assertThat(msg.getRequestBody(), is(not(nullValue())));
        assertThat(msg.getRequestBody().toString().length(), is(0));
        assertThat(msg.getResponseHeader(), is(not(nullValue())));
        assertThat(msg.getTimeElapsedMillis(), is(1234));
        assertThat(msg.getResponseHeader().getStatusCode(), is(200));
        assertThat(msg.getResponseHeader().getHeaders().size(), is(1));
        assertThat(msg.getResponseBody(), is(not(nullValue())));
        assertThat(msg.getResponseBody().toString(), is("The body"));
    }

    private static ZestParam createZestParam() {
        ZestParam zestParam = new ZestParam();
        zestParam.load(new ZapXmlConfiguration());
        return zestParam;
    }

    private static HttpMessage createRequest(String headers) throws HttpMalformedHeaderException {
        return new HttpMessage(new HttpRequestHeader("GET / HTTP/1.1\r\n" + headers));
    }
}
