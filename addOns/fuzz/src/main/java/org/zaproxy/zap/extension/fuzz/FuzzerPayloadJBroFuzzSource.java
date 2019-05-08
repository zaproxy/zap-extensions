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
package org.zaproxy.zap.extension.fuzz;

import org.owasp.jbrofuzz.core.Database;
import org.owasp.jbrofuzz.core.Fuzzer;
import org.owasp.jbrofuzz.core.NoSuchFuzzerException;
import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;
import org.zaproxy.zap.extension.fuzz.payloads.generator.PayloadGenerator;
import org.zaproxy.zap.extension.fuzz.payloads.generator.StringPayloadGenerator;
import org.zaproxy.zap.utils.ResettableAutoCloseableIterator;

public class FuzzerPayloadJBroFuzzSource extends FuzzerPayloadSource {

    private final Database database;
    private final String prototypeId;

    public FuzzerPayloadJBroFuzzSource(String name, Database database, String prototypeId) {
        super(name);
        this.database = database;
        this.prototypeId = prototypeId;
    }

    @Override
    public StringPayloadGenerator getPayloadGenerator() {
        return new JBroFuzzerPayloadGenerator(database, prototypeId);
    }

    @Override
    public StringPayloadGenerator getPayloadGenerator(int limit) {
        return new JBroFuzzerPayloadGenerator(database, prototypeId, limit);
    }

    private static class JBroFuzzerPayloadGenerator implements StringPayloadGenerator {

        private final Database database;
        private final String prototypeId;
        private final long numberOfPayloads;

        public JBroFuzzerPayloadGenerator(Database database, String prototypeId) {
            this(database, prototypeId, -1);
        }

        public JBroFuzzerPayloadGenerator(Database database, String prototypeId, int limit) {
            if (database == null) {
                throw new IllegalArgumentException("Parameter database must not be null.");
            }
            if (prototypeId == null || prototypeId.isEmpty()) {
                throw new IllegalArgumentException(
                        "Parameter prototypeId must not be null nor empty.");
            }

            if (!database.containsPrototype(prototypeId)) {
                throw new IllegalArgumentException(
                        "Provided prototype ID was not found in database: " + prototypeId);
            }

            this.database = database;
            this.prototypeId = prototypeId;
            long nrPaylaods = 0;
            try {
                nrPaylaods = database.createFuzzer(prototypeId, 1).getMaxValue();
            } catch (NoSuchFuzzerException ignore) {
                // The existence was already validated.
            }
            if (limit <= 0) {
                this.numberOfPayloads = nrPaylaods;
            } else {
                this.numberOfPayloads = Math.min(limit, nrPaylaods);
            }
        }

        @Override
        public long getNumberOfPayloads() {
            return numberOfPayloads;
        }

        @Override
        public ResettableAutoCloseableIterator<DefaultPayload> iterator() {
            try {
                return new JBroFuzzerIterator(
                        database.createFuzzer(prototypeId, 1), numberOfPayloads);
            } catch (NoSuchFuzzerException ignore) {
                // The existence was already validated.
                return null;
            }
        }

        @Override
        public PayloadGenerator<DefaultPayload> copy() {
            return this;
        }

        private static class JBroFuzzerIterator
                implements ResettableAutoCloseableIterator<DefaultPayload> {

            private final Fuzzer fuzzer;
            private final long limit;
            private long count;

            public JBroFuzzerIterator(Fuzzer fuzzer, long limit) {
                this.fuzzer = fuzzer;
                this.limit = limit;
                this.count = 0;
            }

            @Override
            public boolean hasNext() {
                if (count >= limit) {
                    return false;
                }
                return fuzzer.hasNext();
            }

            @Override
            public DefaultPayload next() {
                count++;
                return new DefaultPayload(fuzzer.next());
            }

            @Override
            public void reset() {
                count = 0;
                fuzzer.resetCurrentValue();
            }

            @Override
            public void remove() {}

            @Override
            public void close() {}
        }
    }
}
