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

import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.utils.ZapXmlConfiguration;
import org.zaproxy.zest.core.v1.ZestRequest;

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

    private static ZestParam createZestParam() {
        ZestParam zestParam = new ZestParam();
        zestParam.load(new ZapXmlConfiguration());
        return zestParam;
    }

    private static HttpMessage createRequest(String headers) throws HttpMalformedHeaderException {
        return new HttpMessage(new HttpRequestHeader("GET / HTTP/1.1\r\n" + headers));
    }
}
