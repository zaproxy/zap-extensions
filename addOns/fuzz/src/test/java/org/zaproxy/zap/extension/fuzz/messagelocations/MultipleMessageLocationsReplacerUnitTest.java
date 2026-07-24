/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.zap.extension.fuzz.messagelocations;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;

import java.util.ArrayList;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.extension.fuzz.payloads.Payload;
import org.zaproxy.zap.extension.fuzz.payloads.PayloadGeneratorMessageLocation;
import org.zaproxy.zap.extension.fuzz.payloads.generator.DefaultStringPayloadGenerator;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.model.InvalidMessageException;
import org.zaproxy.zap.model.MessageLocation;

/** Unit test for {@link MultipleMessageLocationsReplacer} implementations. */
class MultipleMessageLocationsReplacerUnitTest {

    @Test
    void shouldIterateClusterBombWithLastLocationChangingFastest()
            throws InvalidMessageException, ReplacementException {
        // Given
        RecordingReplacer messageReplacer = new RecordingReplacer();
        MultipleMessageLocationsReplacer<Message> multipleReplacer =
                new MultipleMessageLocationsClusterBombReplacer<>();
        SortedSet<MessageLocationReplacementGenerator<?, ?>> generators =
                generators(List.of("1", "2"), List.of("a", "b"));
        // When
        List<String> orders = iterateAll(multipleReplacer, messageReplacer, generators);
        // Then
        assertThat(orders, contains("1a", "1b", "2a", "2b"));
    }

    @Test
    void shouldIteratePitchforkInLockstep() throws InvalidMessageException, ReplacementException {
        // Given
        RecordingReplacer messageReplacer = new RecordingReplacer();
        MultipleMessageLocationsReplacer<Message> multipleReplacer =
                new MultipleMessageLocationsPitchforkReplacer<>();
        SortedSet<MessageLocationReplacementGenerator<?, ?>> generators =
                generators(List.of("1", "2"), List.of("a", "b"));
        // When
        List<String> orders = iterateAll(multipleReplacer, messageReplacer, generators);
        // Then
        assertThat(orders, contains("1a", "2b"));
    }

    @Test
    void shouldProduceSameOrderForSingleLocationWithBothStrategies()
            throws InvalidMessageException, ReplacementException {
        // Given
        RecordingReplacer messageReplacer = new RecordingReplacer();
        SortedSet<MessageLocationReplacementGenerator<?, ?>> generators =
                generators(List.of("1", "2", "3"));
        // When
        List<String> clusterBomb =
                iterateAll(
                        new MultipleMessageLocationsClusterBombReplacer<>(),
                        messageReplacer,
                        generators);
        List<String> pitchfork =
                iterateAll(
                        new MultipleMessageLocationsPitchforkReplacer<>(),
                        messageReplacer,
                        generators(List.of("1", "2", "3")));
        // Then
        assertThat(clusterBomb, contains("1", "2", "3"));
        assertThat(pitchfork, is(equalTo(clusterBomb)));
    }

    @Test
    void shouldStopPitchforkAtShortestList() throws InvalidMessageException, ReplacementException {
        // Given
        RecordingReplacer messageReplacer = new RecordingReplacer();
        MultipleMessageLocationsReplacer<Message> multipleReplacer =
                new MultipleMessageLocationsPitchforkReplacer<>();
        SortedSet<MessageLocationReplacementGenerator<?, ?>> generators =
                generators(List.of("1", "2", "3"), List.of("a", "b"));
        // When
        List<String> orders = iterateAll(multipleReplacer, messageReplacer, generators);
        // Then
        assertThat(orders, contains("1a", "2b"));
    }

    @Test
    void shouldReportClusterBombCartesianProductSize() {
        // Given
        MultipleMessageLocationsReplacer<Message> multipleReplacer =
                new MultipleMessageLocationsClusterBombReplacer<>();
        SortedSet<MessageLocationReplacementGenerator<?, ?>> generators =
                generators(List.of("1", "2"), List.of("a", "b", "c"));
        // When
        multipleReplacer.init(new RecordingReplacer(), generators);
        // Then
        assertThat(multipleReplacer.getNumberOfReplacements(), is(equalTo(6L)));
    }

    @Test
    void shouldReportPitchforkMinListSize() {
        // Given
        MultipleMessageLocationsReplacer<Message> multipleReplacer =
                new MultipleMessageLocationsPitchforkReplacer<>();
        SortedSet<MessageLocationReplacementGenerator<?, ?>> generators =
                generators(List.of("1", "2"), List.of("a", "b", "c"));
        // When
        multipleReplacer.init(new RecordingReplacer(), generators);
        // Then
        assertThat(multipleReplacer.getNumberOfReplacements(), is(equalTo(2L)));
    }

    @SafeVarargs
    private static SortedSet<MessageLocationReplacementGenerator<?, ?>> generators(
            List<String>... payloadLists) {
        SortedSet<MessageLocationReplacementGenerator<?, ?>> generators = new TreeSet<>();
        for (int i = 0; i < payloadLists.length; i++) {
            DefaultStringPayloadGenerator payloadGenerator =
                    new DefaultStringPayloadGenerator(payloadLists[i]);
            generators.add(
                    new PayloadGeneratorMessageLocation(
                            new TestMessageLocation("loc" + i),
                            payloadGenerator.getNumberOfPayloads(),
                            payloadGenerator.iterator()));
        }
        return generators;
    }

    private static List<String> iterateAll(
            MultipleMessageLocationsReplacer<Message> multipleReplacer,
            RecordingReplacer messageReplacer,
            SortedSet<MessageLocationReplacementGenerator<?, ?>> generators)
            throws InvalidMessageException, ReplacementException {
        multipleReplacer.init(messageReplacer, generators);

        List<String> orders = new ArrayList<>();
        while (multipleReplacer.hasNext()) {
            multipleReplacer.next();
            orders.add(messageReplacer.getLastCombination());
        }
        multipleReplacer.close();
        return orders;
    }

    private static class RecordingReplacer implements MessageLocationReplacer<Message> {

        private final Message message = mock(Message.class);
        private String lastCombination;

        @Override
        public void init(Message message) {}

        @Override
        public boolean supports(MessageLocation location) {
            return true;
        }

        @Override
        public boolean supports(Class<? extends MessageLocation> classLocation) {
            return true;
        }

        @Override
        public Message replace(SortedSet<? extends MessageLocationReplacement<?>> replacements) {
            StringBuilder combination = new StringBuilder();
            for (MessageLocationReplacement<?> replacement : replacements) {
                combination.append(((Payload) replacement.getReplacement()).getValue());
            }
            lastCombination = combination.toString();
            return message;
        }

        String getLastCombination() {
            return lastCombination;
        }
    }

    private static class TestMessageLocation implements MessageLocation {

        private final String id;

        TestMessageLocation(String id) {
            this.id = id;
        }

        @Override
        public Class<? extends Message> getTargetMessageClass() {
            return Message.class;
        }

        @Override
        public String getDescription() {
            return id;
        }

        @Override
        public String getValue() {
            return "";
        }

        @Override
        public boolean overlaps(MessageLocation otherLocation) {
            return otherLocation instanceof TestMessageLocation testLocation
                    && id.equals(testLocation.id);
        }

        @Override
        public int compareTo(MessageLocation other) {
            if (other instanceof TestMessageLocation testLocation) {
                return id.compareTo(testLocation.id);
            }
            return 1;
        }

        @Override
        public int hashCode() {
            return id.hashCode();
        }

        @Override
        public boolean equals(Object obj) {
            return obj instanceof TestMessageLocation testLocation && id.equals(testLocation.id);
        }
    }
}
