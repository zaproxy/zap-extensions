/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;
import org.zaproxy.zap.utils.ResettableAutoCloseableIterator;

/**
 * A {@code PayloadGenerator} that 'generates' numbers in sequence in steps.
 *
 * @author steven
 */
public class NumberPayloadGenerator
        implements StringPayloadGenerator, ResettableAutoCloseableIterator<DefaultPayload> {

    private static final Logger LOGGER = LogManager.getLogger(NumberPayloadGenerator.class);
    private final int fromNo;
    private final int toNo;
    private final int steps;
    private long pos;

    public NumberPayloadGenerator(int fromNo, int toNo, int steps) {
        LOGGER.debug("new NumberPayloadGenerator({},{},{})", fromNo, toNo, steps);
        this.fromNo = fromNo;
        this.toNo = toNo;
        this.steps = steps;
        pos = fromNo;
    }

    @Override
    public long getNumberOfPayloads() {
        int payloadCount = (toNo - fromNo) / steps;
        LOGGER.debug("Number of payloads = {}", payloadCount);
        return payloadCount;
    }

    @Override
    public ResettableAutoCloseableIterator<DefaultPayload> iterator() {
        return this;
    }

    @Override
    public PayloadGenerator<DefaultPayload> copy() {
        return new NumberPayloadGenerator(fromNo, toNo, steps);
    }

    @Override
    public void reset() {
        this.pos = fromNo;
    }

    @Override
    public boolean hasNext() {
        if (steps > 0) {
            return pos <= toNo;
        } else {
            return pos >= toNo;
        }
    }

    @Override
    public DefaultPayload next() {
        DefaultPayload result = new DefaultPayload(Long.toString(pos));
        pos += steps;
        return result;
    }

    @Override
    public void close() {}

    public int getFrom() {
        return fromNo;
    }

    public int getTo() {
        return toNo;
    }

    public int getStep() {
        return steps;
    }

    @Override
    public void remove() {}
}
