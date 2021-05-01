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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;
import org.zaproxy.zap.utils.ResettableAutoCloseableIterator;

public class JsonPayloadGeneratorUnitTest {

    @Test
    public void shouldRejectMissingJsonBase() {
        assertThrows(IllegalArgumentException.class, () -> new JsonPayloadGenerator(null, 1));
    }

    @Test
    public void shouldRejectInvalidJsonBase() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new JsonPayloadGenerator("'an invalid value", 1));
    }

    @Test
    public void shouldHaveAtLeastOnePayload() {
        String originalJson = "{\"x\": \"hello\"}";
        JsonPayloadGenerator generator = new JsonPayloadGenerator(originalJson, 1);
        assertThat(generator.iterator().hasNext(), is(true));
    }

    @Test
    public void shouldGenerateAtLeastOneFuzzedPayload() {
        // Given
        String originalJson = "{\"x\": \"hello\"}";
        JsonPayloadGenerator generator = new JsonPayloadGenerator(originalJson, 2);
        List<String> payloads = new ArrayList<>();
        // When
        Iterator<DefaultPayload> iterator = generator.iterator();
        while (iterator.hasNext()) {
            payloads.add(iterator.next().getValue());
        }
        // Then
        assertThat(payloads, hasAtLeastOneDifferentThan(originalJson));
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

    private static Matcher<List<String>> hasAtLeastOneDifferentThan(String value) {
        JsonElement jsonElement = toGson(value);
        return new BaseMatcher<List<String>>() {

            @Override
            public boolean matches(Object actualValue) {
                @SuppressWarnings("unchecked")
                List<String> values = (List<String>) actualValue;
                if (values.isEmpty()) {
                    return false;
                }

                for (String value : values) {
                    if (!toGson(value).equals(jsonElement)) {
                        return true;
                    }
                }
                return false;
            }

            @Override
            public void describeTo(Description description) {
                description.appendText("at least one value different than ").appendValue(value);
            }

            @Override
            public void describeMismatch(Object item, Description description) {
                @SuppressWarnings("unchecked")
                List<String> values = (List<String>) item;
                if (values.isEmpty()) {
                    description.appendText("has no values");
                } else {
                    description.appendText("had ").appendValue(values);
                }
            }
        };
    }
}
