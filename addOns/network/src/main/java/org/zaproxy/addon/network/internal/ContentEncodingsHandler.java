/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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

import java.util.List;
import org.parosproxy.paros.network.HttpBody;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage.HttpEncodingsHandler;
import org.zaproxy.zap.network.HttpEncoding;
import org.zaproxy.zap.network.HttpEncodingDeflate;
import org.zaproxy.zap.network.HttpEncodingGzip;

public class ContentEncodingsHandler implements HttpEncodingsHandler {

    @Override
    public void handle(HttpHeader header, HttpBody body) {
        String encoding = header.getHeader(HttpHeader.CONTENT_ENCODING);
        if (encoding == null || encoding.isEmpty()) {
            body.setContentEncodings(List.of());
            return;
        }

        List<HttpEncoding> encodings = List.of();
        if (encoding.contains(HttpHeader.DEFLATE)) {
            encodings = List.of(HttpEncodingDeflate.getSingleton());
        } else if (encoding.contains(HttpHeader.GZIP)) {
            encodings = List.of(HttpEncodingGzip.getSingleton());
        } else if (HttpEncodingBrotli.isAvailable() && encoding.contains("br")) {
            encodings = List.of(HttpEncodingBrotli.getSingleton());
        }

        body.setContentEncodings(encodings);
    }
}
