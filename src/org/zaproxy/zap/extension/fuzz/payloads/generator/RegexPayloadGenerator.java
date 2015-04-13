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
package org.zaproxy.zap.extension.fuzz.payloads.generator;

import java.util.ArrayList;
import java.util.List;

import org.zaproxy.zap.extension.fuzz.payloads.DefaultStringPayload;
import org.zaproxy.zap.extension.fuzz.payloads.PayloadCollectionIterator;
import org.zaproxy.zap.extension.fuzz.payloads.StringPayload;
import org.zaproxy.zap.utils.ResettableAutoCloseableIterator;

/**
 * A {@code StringPayloadGenerator} that generates {@code StringPayload}s based on a regular expression.
 */
public class RegexPayloadGenerator implements StringPayloadGenerator {

    private final String regex;
    private final int maxPayloads;
    private final int maxPayloadLength;

    private int numberOfPayloads;

    public RegexPayloadGenerator(String regex, int maxPayloads, int maxPayloadLength) {
        if (regex == null || regex.isEmpty()) {
            throw new IllegalArgumentException("Parameter regex must not be null nor empty.");
        }

        if (maxPayloads <= 0) {
            throw new IllegalArgumentException("Parameter maxPayloads must greater than zero.");
        }

        if (maxPayloadLength < 0) {
            throw new IllegalArgumentException("Parameter maxPayloadLength must not be negative.");
        }

        this.regex = regex;
        this.maxPayloads = maxPayloads;
        this.maxPayloadLength = maxPayloadLength;
        this.numberOfPayloads = calculateNumberOfPayloads(regex, maxPayloads, maxPayloadLength);
    }

    private RegexPayloadGenerator(String regex, int maxPayloads, int maxPayloadLength, int numberOfPayloads) {
        this.regex = regex;
        this.maxPayloads = maxPayloads;
        this.maxPayloadLength = maxPayloadLength;
        this.numberOfPayloads = numberOfPayloads;
    }

    @Override
    public long getNumberOfPayloads() {
        return numberOfPayloads;
    }

    @Override
    public ResettableAutoCloseableIterator<StringPayload> iterator() {
        List<String> payloads = new RegExStringGenerator().regexExpansion(regex, maxPayloadLength, maxPayloads);
        List<StringPayload> tempPayloads = new ArrayList<>(payloads.size());
        for (String payload : payloads) {
            tempPayloads.add(new DefaultStringPayload(payload));
        }
        return new PayloadCollectionIterator<>(tempPayloads);
    }

    @Override
    public RegexPayloadGenerator copy() {
        return new RegexPayloadGenerator(regex, maxPayloads, maxPayloadLength, numberOfPayloads);
    }

    public static int calculateNumberOfPayloads(String regex, int maxPayloads, int maxPayloadLength) {
        try {
            return new RegExStringGenerator().regexExpansion(regex, maxPayloadLength, maxPayloads).size();
        } catch (Error e) {
            // Catch Error, for now, since the calculation of all possibilities might lead to OutOfMemoryError or
            // StackOverflowError if not enough restricted by maxPayloadLength and/or maxPayloads.
            return -1;
        }
    }
}
