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
import java.util.Iterator;
import java.util.List;
import org.apache.commons.collections.iterators.IteratorChain;
import org.zaproxy.zap.extension.fuzz.impl.Utils;
import org.zaproxy.zap.extension.fuzz.payloads.Payload;
import org.zaproxy.zap.utils.EmptyResettableAutoCloseableIterator;
import org.zaproxy.zap.utils.ResettableAutoCloseableIterator;

/**
 * A {@code PayloadGenerator} composed of several {@code PayloadGenerator}s, allowing them to be
 * viewed/handled as a single {@code PayloadGenerator}.
 */
public class CompositePayloadGenerator implements PayloadGenerator {

    private final List<PayloadGenerator> payloadGenerators;

    public CompositePayloadGenerator(List<PayloadGenerator> payloadGenerators) {
        if (payloadGenerators == null) {
            throw new IllegalArgumentException("Parameter payloadGenerators must not be null.");
        }

        this.payloadGenerators = new ArrayList<>(payloadGenerators.size());
        for (PayloadGenerator payloadGenerator : payloadGenerators) {
            this.payloadGenerators.add(payloadGenerator.copy());
        }
    }

    @Override
    public long getNumberOfPayloads() {
        return Utils.sum(
                payloadGenerators.stream().mapToLong(PayloadGenerator::getNumberOfPayloads));
    }

    @Override
    public ResettableAutoCloseableIterator<Payload> iterator() {
        if (payloadGenerators.isEmpty()) {
            return EmptyResettableAutoCloseableIterator.emptyIterator();
        }
        return new CompositeIterator(payloadGenerators);
    }

    @Override
    public PayloadGenerator copy() {
        return new CompositePayloadGenerator(payloadGenerators);
    }

    private static class CompositeIterator implements ResettableAutoCloseableIterator<Payload> {

        private final List<ResettableAutoCloseableIterator<Payload>> allIterators;
        private Iterator<Payload> iteratorChain;

        public CompositeIterator(List<PayloadGenerator> payloadGenerators) {
            allIterators = new ArrayList<>(payloadGenerators.size());
            for (PayloadGenerator payloadGenerator : payloadGenerators) {
                allIterators.add(payloadGenerator.iterator());
            }
            initIteratorChain();
        }

        private void initIteratorChain() {
            @SuppressWarnings("unchecked")
            Iterator<Payload> iterators = new IteratorChain(allIterators);
            iteratorChain = iterators;
        }

        @Override
        public boolean hasNext() {
            return iteratorChain.hasNext();
        }

        @Override
        public Payload next() {
            return iteratorChain.next();
        }

        @Override
        public void remove() {}

        @Override
        public void reset() {
            for (ResettableAutoCloseableIterator<Payload> iterator : allIterators) {
                iterator.reset();
            }
            initIteratorChain();
        }

        @Override
        public void close() {
            for (ResettableAutoCloseableIterator<Payload> iterator : allIterators) {
                iterator.close();
            }
        }
    }
}
