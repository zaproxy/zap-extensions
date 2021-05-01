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

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.apache.commons.codec.binary.Hex;
import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;

public abstract class AbstractStringHashProcessor extends AbstractCharsetProcessor<DefaultPayload>
        implements DefaultPayloadProcessor {

    protected static final Hex HEX_ASCII = new Hex(StandardCharsets.US_ASCII.name());

    private final boolean upperCase;

    public AbstractStringHashProcessor() {
        this(false);
    }

    public AbstractStringHashProcessor(boolean upperCase) {
        super();

        this.upperCase = upperCase;
    }

    public AbstractStringHashProcessor(String charsetName) {
        this(charsetName, false);
    }

    public AbstractStringHashProcessor(String charsetName, boolean upperCase) {
        super(charsetName);

        this.upperCase = upperCase;
    }

    public AbstractStringHashProcessor(Charset charset) {
        this(charset, false);
    }

    public AbstractStringHashProcessor(Charset charset, boolean upperCase) {
        super(charset);

        this.upperCase = upperCase;
    }

    public boolean isUpperCase() {
        return upperCase;
    }

    protected abstract MessageDigest getMessageDigest();

    @Override
    public DefaultPayload process(DefaultPayload payload) {
        MessageDigest messageDigest = getMessageDigest();
        messageDigest.reset();
        messageDigest.update(payload.getValue().getBytes(getCharset()));
        payload.setValue(new String(HEX_ASCII.encodeHex(messageDigest.digest(), !upperCase)));
        return payload;
    }

    protected static MessageDigest createMessageDigest(String algorithm)
            throws NoSuchAlgorithmException {
        return MessageDigest.getInstance(algorithm);
    }
}
