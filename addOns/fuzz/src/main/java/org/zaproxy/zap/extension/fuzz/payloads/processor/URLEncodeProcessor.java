/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.fuzz.payloads.processor;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;

public class URLEncodeProcessor extends AbstractCharsetProcessor<DefaultPayload>
        implements DefaultPayloadProcessor {

    public URLEncodeProcessor() {
        super();
    }

    public URLEncodeProcessor(String charsetName) {
        super(charsetName);
    }

    public URLEncodeProcessor(Charset charset) {
        super(charset);
    }

    @Override
    public DefaultPayload process(DefaultPayload payload) {
        try {
            payload.setValue(URLEncoder.encode(payload.getValue(), getCharsetName()));
        } catch (UnsupportedEncodingException ignore) {
            // Shouldn't happen, the encoding was already validated.
        }
        return payload;
    }

    @Override
    public URLEncodeProcessor copy() {
        return this;
    }
}
