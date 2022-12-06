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
package org.zaproxy.addon.network.internal.client.apachev5;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.zaproxy.addon.network.internal.client.apachev5.LenientMessageParserFactory.LINE_PARSER;

import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.config.Http1Config;
import org.apache.hc.core5.http.io.HttpMessageParser;
import org.apache.hc.core5.util.CharArrayBuffer;
import org.junit.jupiter.api.Test;

/** Unit test for  {@link LenientMessageParserFactory}. */
class LenientMessageParserFactoryUnitTest {

    @Test
    void shouldParseValidLine() throws Exception {
        // Given
        CharArrayBuffer buffer = new CharArrayBuffer(100);
        String headerContent = "Header: with separator";
        buffer.append(headerContent);
        // When
        Header header = LINE_PARSER.parseHeader(buffer);
        // Then
        assertThat(header.getName(), is(equalTo("Header")));
        assertThat(header.getValue(), is(equalTo("with separator")));
    }

    @Test
    void shouldParseLineWithoutNameValuePairSeparator() throws Exception {
        // Given
        CharArrayBuffer buffer = new CharArrayBuffer(100);
        String headerContent = "Header without separator";
        buffer.append(headerContent);
        // When
        Header header = LINE_PARSER.parseHeader(buffer);
        // Then
        assertThat(header.getName(), is(equalTo(headerContent)));
        assertThat(header.getValue(), is(equalTo("")));
    }

    @Test
    void shouldCreateMessageParser() {
        // Given
        Http1Config h1Config = Http1Config.DEFAULT;
        LenientMessageParserFactory parserFactory = new LenientMessageParserFactory();
        // When
        HttpMessageParser<ClassicHttpResponse> parser = parserFactory.create(h1Config);
        // Then
        assertThat(parser, is(notNullValue()));
    }
}
