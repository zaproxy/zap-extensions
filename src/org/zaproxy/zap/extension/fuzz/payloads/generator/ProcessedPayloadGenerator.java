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

import java.util.List;

import org.zaproxy.zap.extension.fuzz.payloads.Payload;
import org.zaproxy.zap.extension.fuzz.payloads.processor.PayloadProcessingException;
import org.zaproxy.zap.extension.fuzz.payloads.processor.PayloadProcessor;
import org.zaproxy.zap.utils.EmptyResettableAutoCloseableIterator;
import org.zaproxy.zap.utils.ResettableAutoCloseableIterator;

public class ProcessedPayloadGenerator<T1, T2 extends Payload<T1>> implements PayloadGenerator<T1, T2> {

    private final PayloadGenerator<T1, T2> payloadGenerator;
    private final List<PayloadProcessor<T1, T2>> processors;

    public ProcessedPayloadGenerator(PayloadGenerator<T1, T2> payloadGenerator, List<PayloadProcessor<T1, T2>> processors) {
        this.payloadGenerator = payloadGenerator;
        this.processors = processors;
    }

    @Override
    public long getNumberOfPayloads() {
        return payloadGenerator.getNumberOfPayloads();
    }

    @Override
    public ResettableAutoCloseableIterator<T2> iterator() {
        return new ProcessedPayaloadGeneratorIterator<>(payloadGenerator, processors);
    }

    @Override
    public ProcessedPayloadGenerator<T1, T2> copy() {
        return new ProcessedPayloadGenerator<>(payloadGenerator, processors);
    }

    private static class ProcessedPayaloadGeneratorIterator<T, E extends Payload<T>> implements
            ResettableAutoCloseableIterator<E> {

        private final PayloadGenerator<T, E> payloadGenerator;
        private final List<PayloadProcessor<T, E>> processors;

        private ResettableAutoCloseableIterator<E> payloadIterator;

        public ProcessedPayaloadGeneratorIterator(
                PayloadGenerator<T, E> payloadGenerator,
                List<PayloadProcessor<T, E>> processors) {
            this.payloadGenerator = payloadGenerator;
            this.processors = processors;

            initIterator();
        }

        private void initIterator() {
            payloadIterator = payloadGenerator.iterator();
            if (payloadIterator == null) {
                payloadIterator = EmptyResettableAutoCloseableIterator.emptyIterator();
            }
        }

        @Override
        public boolean hasNext() {
            return payloadIterator.hasNext();
        }

        @Override
        public E next() {
            E value = payloadIterator.next();
            for (PayloadProcessor<T, E> processor : processors) {
                try {
                    value = processor.process(value);
                } catch (PayloadProcessingException e) {
                    throw new PayloadGenerationException("An error occurred while processing the payload: " + e.toString(), e);
                }
            }
            return value;
        }

        @Override
        public void remove() {
        }

        @Override
        public void reset() {
            initIterator();
        }

        @Override
        public void close() throws Exception {
            payloadIterator.close();
        }

    }
}
