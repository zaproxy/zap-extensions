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

import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.config.Http1Config;
import org.apache.hc.core5.http.impl.io.DefaultClassicHttpResponseFactory;
import org.apache.hc.core5.http.impl.io.DefaultHttpResponseParser;
import org.apache.hc.core5.http.io.HttpMessageParser;
import org.apache.hc.core5.http.io.HttpMessageParserFactory;
import org.apache.hc.core5.http.message.BasicHeader;
import org.apache.hc.core5.http.message.BasicLineParser;
import org.apache.hc.core5.http.message.LineParser;
import org.apache.hc.core5.util.CharArrayBuffer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** A {@link HttpMessageParserFactory} that accepts malformed headers. */
public class LenientMessageParserFactory implements HttpMessageParserFactory<ClassicHttpResponse> {

    private static final Logger LOGGER = LogManager.getLogger(LenientMessageParserFactory.class);

    static final LineParser LINE_PARSER =
            new BasicLineParser() {

                @Override
                public Header parseHeader(CharArrayBuffer buffer) {
                    try {
                        return super.parseHeader(buffer);
                    } catch (ParseException ex) {
                        String line = buffer.toString();
                        LOGGER.warn("Accepting malformed HTTP header line: {}", line);
                        return new BasicHeader(line, "");
                    }
                }
            };

    @Override
    public HttpMessageParser<ClassicHttpResponse> create(Http1Config h1Config) {
        return new DefaultHttpResponseParser(
                LINE_PARSER, DefaultClassicHttpResponseFactory.INSTANCE, h1Config);
    }
}
