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

import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.Matchers.*;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.*;

import com.google.gson.*;
import java.util.*;
import org.junit.*;
import org.zaproxy.zap.extension.fuzz.payloads.*;
import org.zaproxy.zap.utils.*;

public class JsonPayloadGeneratorUnitTest {

    @Test(expected = IllegalArgumentException.class)
    public void shouldRejectMissingJsonBase() {
        new JsonPayloadGenerator(null, 1);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldRejectInvalidJsonBase() {
        new JsonPayloadGenerator("'an invalid value", 1);
    }

    @Test
    public void shouldHaveAtLeastOnePayload() {
        String originalJson = "{\"x\": \"hello\"}";
        JsonPayloadGenerator generator = new JsonPayloadGenerator(originalJson, 1);
        assertThat(generator.iterator().hasNext(), is(true));
    }

    @Test
    public void shouldGenerateOneFuzzedPayload() {
        String originalJson = "{\"x\": \"hello\"}";
        JsonPayloadGenerator generator = new JsonPayloadGenerator(originalJson, 1);
        DefaultPayload next = generator.iterator().next();
        JsonElement json = toGson(next.getValue());
        assertThat(json, is(not(toGson(originalJson))));
    }

    @Test
    public void shouldNotGenerateTooManyPayloads() {
        String originalJson = "{\"x\": \"hello\"}";
        JsonPayloadGenerator generator = new JsonPayloadGenerator(originalJson, 1);
        ResettableAutoCloseableIterator<DefaultPayload> iterator = generator.iterator();
        iterator.next();
        assertThat(iterator.hasNext(), is(false));
    }

    @Test
    public void shouldGenerateMultipleMutants() {
        String originalJson = "{\"x\": \"hello\"}";
        JsonPayloadGenerator generator = new JsonPayloadGenerator(originalJson, 20);
        ResettableAutoCloseableIterator<DefaultPayload> iterator = generator.iterator();
        Set<String> mutants = new HashSet<>();
        while (iterator.hasNext()) {
            mutants.add(iterator.next().toString());
        }
        // Don't generate an infinite number of mutants
        // Even if you request 100 mutants, the library
        // will generate a finite number of mutants
        assertThat(mutants.size(), greaterThan(15));
    }

    private static JsonElement toGson(String originalJson) {
        return new JsonParser().parse(originalJson);
    }
}
