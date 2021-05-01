/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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

import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.natpryce.snodge.JsonMutator;
import java.util.Iterator;
import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;
import org.zaproxy.zap.utils.ResettableAutoCloseableIterator;

public class JsonPayloadGenerator implements StringPayloadGenerator {
    private final String json;
    private final int numberOfPayloads;
    private final JsonElement originalJson;

    public JsonPayloadGenerator(String json, int numberOfPayloads) {
        this.originalJson = createElement(json);
        this.json = json;
        this.numberOfPayloads = numberOfPayloads;
    }

    private JsonElement createElement(String json) {
        if (json == null) {
            throw new IllegalArgumentException("The provided json must not be null");
        }
        try {
            return new JsonParser().parse(json);
        } catch (Exception e) {
            throw new IllegalArgumentException("The provided json must be valid: " + json);
        }
    }

    @Override
    public long getNumberOfPayloads() {
        return numberOfPayloads;
    }

    @Override
    public ResettableAutoCloseableIterator<DefaultPayload> iterator() {
        return new JsonPayloadIterator(numberOfPayloads, originalJson);
    }

    @Override
    public PayloadGenerator<DefaultPayload> copy() {
        return new JsonPayloadGenerator(json, numberOfPayloads);
    }

    public String getJson() {
        return this.json;
    }

    private static class JsonPayloadIterator
            implements ResettableAutoCloseableIterator<DefaultPayload> {
        private final int numberOfPayloads;
        private final JsonElement originalJson;
        private Iterator<JsonElement> mutant;
        private int count;

        private JsonPayloadIterator(int numberOfPayloads, JsonElement originalJson) {
            this.numberOfPayloads = numberOfPayloads;
            this.originalJson = originalJson;
            reset();
        }

        @Override
        public void close() {}

        @Override
        public void reset() {
            JsonMutator mutator = new JsonMutator();
            mutant = mutator.mutate(this.originalJson, this.numberOfPayloads).iterator();
            this.count = 0;
        }

        @Override
        public boolean hasNext() {
            return this.count < this.numberOfPayloads;
        }

        @Override
        public DefaultPayload next() {
            this.count++;
            JsonElement jsonElement = this.mutant.next();
            return new DefaultPayload(jsonElement.toString());
        }
    }
}
