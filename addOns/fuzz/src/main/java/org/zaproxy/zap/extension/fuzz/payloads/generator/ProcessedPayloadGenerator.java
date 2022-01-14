/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
import org.zaproxy.zap.extension.fuzz.ExtensionFuzz;
import org.zaproxy.zap.extension.fuzz.payloads.Payload;
import org.zaproxy.zap.extension.fuzz.payloads.processor.PayloadProcessingException;
import org.zaproxy.zap.extension.fuzz.payloads.processor.PayloadProcessor;
import org.zaproxy.zap.utils.EmptyResettableAutoCloseableIterator;
import org.zaproxy.zap.utils.ResettableAutoCloseableIterator;
import org.zaproxy.zap.utils.Stats;

public class ProcessedPayloadGenerator<T extends Payload> implements PayloadGenerator<T> {

    private final PayloadGenerator<T> payloadGenerator;
    private final List<PayloadProcessor<T>> processors;

    public ProcessedPayloadGenerator(
            PayloadGenerator<T> payloadGenerator, List<PayloadProcessor<T>> processors) {
        this.payloadGenerator = payloadGenerator;
        this.processors = processors;
    }

    @Override
    public long getNumberOfPayloads() {
        return payloadGenerator.getNumberOfPayloads();
    }

    @Override
    public ResettableAutoCloseableIterator<T> iterator() {
        return new ProcessedPayaloadGeneratorIterator<>(payloadGenerator, processors);
    }

    @Override
    public ProcessedPayloadGenerator<T> copy() {
        return new ProcessedPayloadGenerator<>(payloadGenerator, processors);
    }

    private static class ProcessedPayaloadGeneratorIterator<E extends Payload>
            implements ResettableAutoCloseableIterator<E> {

        private final PayloadGenerator<E> payloadGenerator;
        private final List<PayloadProcessor<E>> processors;

        private ResettableAutoCloseableIterator<E> payloadIterator;

        public ProcessedPayaloadGeneratorIterator(
                PayloadGenerator<E> payloadGenerator, List<PayloadProcessor<E>> processors) {
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
            for (PayloadProcessor<E> processor : processors) {
                try {
                    value = processor.process(value);
                    Stats.incCounter(ExtensionFuzz.PAYLOAD_PROCESSOR_RUN_STATS);
                } catch (PayloadProcessingException e) {
                    Stats.incCounter(ExtensionFuzz.PAYLOAD_PROCESSOR_ERROR_STATS);
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
            initIterator();
        }

        @Override
        public void close() {
            payloadIterator.close();
        }
    }
}
