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
package org.zaproxy.zap.extension.fuzz.impl;

import java.util.ArrayList;
import java.util.List;
import org.zaproxy.zap.extension.fuzz.payloads.Payload;
import org.zaproxy.zap.extension.fuzz.payloads.generator.PayloadGenerationException;
import org.zaproxy.zap.extension.fuzz.payloads.generator.PayloadGenerator;
import org.zaproxy.zap.extension.fuzz.payloads.processor.PayloadProcessingException;
import org.zaproxy.zap.extension.fuzz.payloads.processor.PayloadProcessor;
import org.zaproxy.zap.utils.ResettableAutoCloseableIterator;

class PayloadsProcessedIterator<E extends Payload>
        implements ResettableAutoCloseableIterator<E>, PayloadGenerator<E> {

    private final List<PayloadProcessor<E>> processors;
    private ResettableAutoCloseableIterator<E> payloadIterator;

    public PayloadsProcessedIterator(
            ResettableAutoCloseableIterator<E> payloadIterator,
            List<PayloadProcessor<E>> processors) {
        this.payloadIterator = payloadIterator;
        this.processors = new ArrayList<>(processors);
    }

    @Override
    public boolean hasNext() {
        return payloadIterator.hasNext();
    }

    @Override
    public E next() {
        E value = (E) payloadIterator.next().copy();
        for (PayloadProcessor<E> processor : processors) {
            try {
                value = processor.process(value);
            } catch (PayloadProcessingException e) {
                throw new PayloadGenerationException(
                        "An error occurred while processing the payload: " + e.toString(), e);
            }
        }
        return value;
    }

    @Override
    public void remove() {}

    @Override
    public void reset() {
        payloadIterator.reset();
        for (int i = 0; i < processors.size(); i++) {
            processors.set(i, processors.get(i).copy());
        }
    }

    @Override
    public void close() {
        payloadIterator.close();
    }

    @Override
    public long getNumberOfPayloads() {
        return 0;
    }

    @Override
    public ResettableAutoCloseableIterator<E> iterator() {
        return this;
    }

    @Override
    public PayloadGenerator<E> copy() {
        return this;
    }
}
