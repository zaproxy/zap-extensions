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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA256HashProcessor extends AbstractStringHashProcessor {

    private static final String SHA256_ALGORITHM = "SHA-256";

    private final MessageDigest messageDigest;

    public SHA256HashProcessor() {
        this(false);
    }

    public SHA256HashProcessor(boolean upperCase) {
        super(upperCase);
        messageDigest = createSHA256MessageDigest();
    }

    public SHA256HashProcessor(String charsetName) {
        this(charsetName, false);
    }

    public SHA256HashProcessor(String charsetName, boolean upperCase) {
        super(charsetName, upperCase);
        messageDigest = createSHA256MessageDigest();
    }

    public SHA256HashProcessor(Charset charset) {
        this(charset, false);
    }

    public SHA256HashProcessor(Charset charset, boolean upperCase) {
        super(charset, upperCase);
        messageDigest = createSHA256MessageDigest();
    }

    private static MessageDigest createSHA256MessageDigest() {
        try {
            return createMessageDigest(SHA256_ALGORITHM);
        } catch (NoSuchAlgorithmException ignore) {
            // SHA-256 is one of the standard MessageDigest algorithms
            // that Java implementations are required to support.
        }
        return null;
    }

    @Override
    protected MessageDigest getMessageDigest() {
        return messageDigest;
    }

    @Override
    public SHA256HashProcessor copy() {
        return new SHA256HashProcessor(getCharset(), isUpperCase());
    }
}
