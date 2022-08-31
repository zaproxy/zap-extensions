/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.spider.parser;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.spider.SpiderParam;
import org.zaproxy.zap.model.ValueGenerator;
import org.zaproxy.zap.network.HttpResponseBody;

/** Unit test for {@link ParseContext}. */
class ParseContextUnitTest {

    private SpiderParam spiderParam;
    private ValueGenerator valueGenerator;
    private HttpMessage httpMessage;
    private String responseData;
    private String path;
    private String uri;
    private int depth;

    private ParseContext ctx;

    @BeforeEach
    void setup() throws Exception {
        spiderParam = mock(SpiderParam.class);
        valueGenerator = mock(ValueGenerator.class);
        httpMessage = mock(HttpMessage.class);
        responseData = "<html></html>";
        path = "/path";
        uri = "https://example.com" + path;
        depth = 1;

        HttpRequestHeader requestHeader = mock(HttpRequestHeader.class);
        given(requestHeader.getURI()).willReturn(new URI(uri, true));
        given(httpMessage.getRequestHeader()).willReturn(requestHeader);

        HttpResponseBody responseBody = mock(HttpResponseBody.class);
        given(responseBody.toString()).willReturn(responseData);
        given(httpMessage.getResponseBody()).willReturn(responseBody);
    }

    @Test
    void shouldCreateWithGivenValues() {
        // Given / When
        ctx = new ParseContext(spiderParam, valueGenerator, httpMessage, path, depth);
        // Then
        assertThat(ctx.getSpiderParam(), is(sameInstance(spiderParam)));
        assertThat(ctx.getValueGenerator(), is(sameInstance(valueGenerator)));
        assertThat(ctx.getHttpMessage(), is(sameInstance(httpMessage)));
        assertThat(ctx.getPath(), is(equalTo(path)));
        assertThat(ctx.getDepth(), is(equalTo(depth)));
        assertThat(ctx.getBaseUrl(), is(equalTo(uri)));
        assertThat(ctx.getSource(), is(notNullValue()));
        assertThat(ctx.getSource().toString(), is(equalTo(responseData)));
    }

    @Test
    void shouldThrowWhenCreatingWithNullSpiderParam() {
        // Given
        SpiderParam spiderParam = null;
        // When / Then
        assertThrows(
                NullPointerException.class,
                () -> new ParseContext(spiderParam, valueGenerator, httpMessage, path, depth));
    }

    @Test
    void shouldThrowWhenCreatingWithNullValueGenerator() {
        // Given
        ValueGenerator valueGenerator = null;
        // When / Then
        assertThrows(
                NullPointerException.class,
                () -> new ParseContext(spiderParam, valueGenerator, httpMessage, path, depth));
    }

    @Test
    void shouldThrowWhenCreatingWithNullHttpMessage() {
        // Given
        HttpMessage httpMessage = null;
        // When / Then
        assertThrows(
                NullPointerException.class,
                () -> new ParseContext(spiderParam, valueGenerator, httpMessage, path, depth));
    }

    @Test
    void shouldCreateBaseUrlLazily() {
        // Given / When
        ctx = new ParseContext(spiderParam, valueGenerator, httpMessage, path, depth);
        // Then
        verify(httpMessage, times(0)).getRequestHeader();
    }

    @Test
    void shouldCreateBaseUrlOnce() {
        // Given
        ctx = new ParseContext(spiderParam, valueGenerator, httpMessage, path, depth);
        // When
        ctx.getBaseUrl();
        ctx.getBaseUrl();
        // Then
        verify(httpMessage).getRequestHeader();
    }

    @Test
    void shouldCreateSourceLazily() {
        // Given / When
        ctx = new ParseContext(spiderParam, valueGenerator, httpMessage, path, depth);
        // Then
        verify(httpMessage, times(0)).getResponseBody();
    }

    @Test
    void shouldCreateSourceOnce() {
        // Given
        ctx = new ParseContext(spiderParam, valueGenerator, httpMessage, path, depth);
        // When
        ctx.getSource();
        ctx.getSource();
        // Then
        verify(httpMessage).getResponseBody();
    }
}
