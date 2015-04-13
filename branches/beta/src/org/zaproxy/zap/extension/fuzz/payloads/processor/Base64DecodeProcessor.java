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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;

import org.apache.log4j.Logger;
import org.parosproxy.paros.extension.encoder.Base64;
import org.zaproxy.zap.extension.fuzz.payloads.StringPayload;

public class Base64DecodeProcessor extends AbstractCharsetProcessor<String, StringPayload> implements StringPayloadProcessor {

    private static final Logger LOGGER = Logger.getLogger(Base64DecodeProcessor.class);

    public Base64DecodeProcessor() {
        super();
    }

    public Base64DecodeProcessor(String charsetName) {
        super(charsetName);
    }

    public Base64DecodeProcessor(Charset charset) {
        super(charset);
    }

    @Override
    public StringPayload process(StringPayload payload) {
        try {
            payload.setValue(new String(Base64.decode(payload.getValue(), Base64.NO_OPTIONS), getCharsetName()));
        } catch (UnsupportedEncodingException ignore) {
            // Shouldn't happen, the encoding was already validated.
        } catch (IOException e) {
            LOGGER.warn("An error occurred while encoding the payload: " + e.getMessage());
        }
        return payload;
    }

    @Override
    public Base64DecodeProcessor copy() {
        return this;
    }

}
