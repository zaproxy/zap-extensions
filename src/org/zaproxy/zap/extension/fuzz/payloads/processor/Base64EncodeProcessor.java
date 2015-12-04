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
import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;

public class Base64EncodeProcessor extends AbstractCharsetProcessor<DefaultPayload> implements DefaultPayloadProcessor {

    private static final Logger LOGGER = Logger.getLogger(Base64EncodeProcessor.class);

    private final boolean breakLines;

    public Base64EncodeProcessor() {
        this(true);
    }

    public Base64EncodeProcessor(boolean breakLines) {
        super();
        this.breakLines = breakLines;
    }

    public Base64EncodeProcessor(String charsetName) {
        super(charsetName);
        this.breakLines = false;
    }

    public Base64EncodeProcessor(Charset charset) {
        this(charset, true);
    }

    public Base64EncodeProcessor(String charsetName, boolean breakLines) {
        super(charsetName);
        this.breakLines = breakLines;
    }

    public Base64EncodeProcessor(Charset charset, boolean breakLines) {
        super(charset);
        this.breakLines = breakLines;
    }

    @Override
    public DefaultPayload process(DefaultPayload payload) {
        try {
            payload.setValue(Base64.encodeBytes(getBytes(payload.getValue()), breakLines
                    ? Base64.DO_BREAK_LINES
                    : Base64.NO_OPTIONS));
        } catch (IOException e) {
            LOGGER.warn("An error occurred while encoding the payload: " + e.getMessage());
        }
        return payload;
    }

    public byte[] getBytes(String buf) {
        byte[] result = null;
        try {
            result = buf.getBytes(getCharsetName());
        } catch (UnsupportedEncodingException ignore) {
            // Shouldn't happen, the encoding was already validated.
        }
        return result;
    }

    @Override
    public Base64EncodeProcessor copy() {
        return this;
    }

}
