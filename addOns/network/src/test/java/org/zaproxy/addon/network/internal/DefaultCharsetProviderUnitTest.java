/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.addon.network.internal;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.network.HttpBody;
import org.parosproxy.paros.network.HttpHeader;

/** Unit test for {@link DefaultCharsetProvider}. */
class DefaultCharsetProviderUnitTest {

    private DefaultCharsetProvider provider;

    @BeforeEach
    void setUp() {
        provider = new DefaultCharsetProvider();
    }

    @ParameterizedTest
    @ValueSource(strings = {"charset-1", "  charset-2  "})
    void shouldReturnHeaderCharsetIfNotBlank(String charset) {
        // Given
        HttpHeader header = mock();
        given(header.getCharset()).willReturn(charset);
        HttpBody body = mock();
        // When / Then
        assertThat(provider.get(header, body), is(equalTo(charset)));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "\t"})
    void shouldReturnNullCharsetIfBlankHeaderCharsetAndNotApplicationJson(String charset) {
        // Given
        HttpHeader header = mock();
        given(header.getCharset()).willReturn(charset);
        HttpBody body = mock();
        // When / Then
        assertThat(provider.get(header, body), is(nullValue()));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "\t"})
    void shouldReturnUtf8CharsetIfBlankHeaderCharsetAndApplicationJson(String charset) {
        // Given
        HttpHeader header = mock();
        given(header.getCharset()).willReturn(charset);
        given(header.hasContentType(HttpHeader.JSON_CONTENT_TYPE)).willReturn(true);
        HttpBody body = mock();
        // When / Then
        assertThat(provider.get(header, body), is(equalTo("UTF-8")));
    }
}
