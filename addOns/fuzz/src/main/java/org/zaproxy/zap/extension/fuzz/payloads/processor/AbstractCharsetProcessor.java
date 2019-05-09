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
import java.nio.charset.IllegalCharsetNameException;
import java.nio.charset.StandardCharsets;
import java.nio.charset.UnsupportedCharsetException;
import org.zaproxy.zap.extension.fuzz.payloads.Payload;

/**
 * A {@code PayloadProcessor} that has/uses a {@code Charset} in the processing of {@code Payload}s.
 *
 * @param <T> the type of payload
 * @see Charset
 * @see Payload
 * @see PayloadProcessor
 */
public abstract class AbstractCharsetProcessor<T extends Payload> implements PayloadProcessor<T> {

    /** The {@code Charset}, never {@code null}. */
    private final Charset charset;

    public AbstractCharsetProcessor() {
        this.charset = StandardCharsets.UTF_8;
    }

    public AbstractCharsetProcessor(Charset charset) {
        if (charset == null) {
            throw new IllegalArgumentException("Parameter charset must no be null.");
        }
        this.charset = charset;
    }

    public AbstractCharsetProcessor(String charsetName) {
        if (charsetName == null) {
            throw new IllegalArgumentException("Parameter charsetName must no be null.");
        }

        try {
            charset = Charset.forName(charsetName);
        } catch (IllegalCharsetNameException | UnsupportedCharsetException e) {
            throw new IllegalArgumentException(
                    "Parameter charsetName does not represent a valid or supported charset name.");
        }
    }

    /**
     * Gets the name of the charset.
     *
     * @return the name of the charset.
     */
    public String getCharsetName() {
        return charset.name();
    }

    /**
     * Gets the charset.
     *
     * @return the charset.
     */
    public Charset getCharset() {
        return charset;
    }
}
