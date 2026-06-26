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
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.model.InvalidMessageException;
import org.zaproxy.zap.model.MessageLocation;

/** Unit test for {@link MultipleMessageLocationsReplacer} implementations. */
class MultipleMessageLocationsReplacerUnitTest {

    @Test
    void clusterBombShouldIterateWithLastLocationChangingFastest()
            throws InvalidMessageException, ReplacementException {
        // Given
        var replacer = createReplacer();
        var orders =
                iterateAll(
                        new MultipleMessageLocationsClusterBombReplacer<>(),
                        replacer,
                        "1",
                        "2",
                        "a",
                        "b");
        // Then
        assertThat(orders, contains("1a", "1b", "2a", "2b"));
    }

    @Test
    void pitchforkShouldIterateInLockstepOrder()
            throws InvalidMessageException, ReplacementException {
        // Given
        var replacer = createReplacer();
        var orders =
                iterateAll(
                        new MultipleMessageLocationsPitchforkReplacer<>(),
                        replacer,
                        "1",
                        "2",
                        "a",
                        "b");
        // Then
        assertThat(orders, contains("1a", "2b"));
    }

    @Test
    void strategiesShouldDifferWithThreeLocations()
            throws InvalidMessageException, ReplacementException {
        // Given
        var replacer = createReplacer();
        var clusterBomb =
                iterateAll(
                        new MultipleMessageLocationsClusterBombReplacer<>(),
                        replacer,
                        "1",
                        "2",
                        "a",
                        "b",
                        "x",
                        "y");
        var pitchfork =
                iterateAll(
                        new MultipleMessageLocationsPitchforkReplacer<>(),
                        replacer,
                        "1",
                        "2",
                        "a",
                        "b",
                        "x",
                        "y");
        // Then
        assertThat(clusterBomb, contains("1ax", "1ay", "1bx", "1by", "2ax", "2ay", "2bx", "2by"));
        assertThat(pitchfork, contains("1ax", "2by"));
    }

    @Test
    void singleLocationShouldProduceSameOrderForBothStrategies()
            throws InvalidMessageException, ReplacementException {
        // Given
        var replacer = createReplacer();
        var clusterBomb =
                iterateAll(
                        new MultipleMessageLocationsClusterBombReplacer<>(),
                        replacer,
                        List.of("1", "2", "3"));
        var pitchfork =
                iterateAll(
                        new MultipleMessageLocationsPitchforkReplacer<>(),
                        replacer,
                        List.of("1", "2", "3"));
        // Then
        assertThat(clusterBomb, contains("1", "2", "3"));
        assertThat(pitchfork, is(equalTo(clusterBomb)));
    }

    @Test
    void clusterBombShouldReportCartesianProductSize() throws Exception {
        // Given
        var messageReplacer = createReplacer();
        var multipleReplacer = new MultipleMessageLocationsClusterBombReplacer<Message>();
        SortedSet<MessageLocationReplacementGenerator<?, ?>> generators = new TreeSet<>();
        generators.add(new TestGenerator(new TestMessageLocation("loc0"), List.of("1", "2")));
        generators.add(new TestGenerator(new TestMessageLocation("loc1"), List.of("a", "b", "c")));
        multipleReplacer.init(messageReplacer, generators);
        // Then
        assertThat(multipleReplacer.getNumberOfReplacements(), is(equalTo(6L)));
    }

    @Test
    void pitchforkShouldReportMinListSize() throws Exception {
        // Given
        var messageReplacer = createReplacer();
        var multipleReplacer = new MultipleMessageLocationsPitchforkReplacer<Message>();
        SortedSet<MessageLocationReplacementGenerator<?, ?>> generators = new TreeSet<>();
        generators.add(new TestGenerator(new TestMessageLocation("loc0"), List.of("1", "2")));
        generators.add(new TestGenerator(new TestMessageLocation("loc1"), List.of("a", "b", "c")));
        multipleReplacer.init(messageReplacer, generators);
        // Then
        assertThat(multipleReplacer.getNumberOfReplacements(), is(equalTo(2L)));
    }

    private static RecordingReplacer createReplacer() {
        return new RecordingReplacer(mock(Message.class));
    }

    private static List<String> iterateAll(
            MultipleMessageLocationsReplacer<Message> multipleReplacer,
            RecordingReplacer messageReplacer,
            String... payloadsByGenerator)
            throws InvalidMessageException, ReplacementException {
        SortedSet<MessageLocationReplacementGenerator<?, ?>> generators = new TreeSet<>();
        int generatorCount = payloadsByGenerator.length / 2;
        for (int i = 0; i < generatorCount; i++) {
            String locId = "loc" + i;
            generators.add(
                    new TestGenerator(
                            new TestMessageLocation(locId),
                            List.of(payloadsByGenerator[i * 2], payloadsByGenerator[i * 2 + 1])));
        }
        return iterateGenerators(multipleReplacer, messageReplacer, generators);
    }

    private static List<String> iterateAll(
            MultipleMessageLocationsReplacer<Message> multipleReplacer,
            RecordingReplacer messageReplacer,
            List<String> payloads)
            throws InvalidMessageException, ReplacementException {
        SortedSet<MessageLocationReplacementGenerator<?, ?>> generators = new TreeSet<>();
        generators.add(new TestGenerator(new TestMessageLocation("loc0"), payloads));
        return iterateGenerators(multipleReplacer, messageReplacer, generators);
    }

    private static List<String> iterateGenerators(
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

        private final Message message;
        private String lastCombination;

        RecordingReplacer(Message message) {
            this.message = message;
        }

        @Override
        public void init(Message message) {}

        @Override
        public boolean supports(MessageLocation location) {
            return location instanceof TestMessageLocation;
        }

        @Override
        public boolean supports(Class<? extends MessageLocation> classLocation) {
            return TestMessageLocation.class.isAssignableFrom(classLocation);
        }

        @Override
        public Message replace(SortedSet<? extends MessageLocationReplacement<?>> replacements) {
            StringBuilder combination = new StringBuilder();
            for (MessageLocationReplacement<?> replacement : replacements) {
                combination.append(
                        ((StringMessageLocationReplacement) replacement).getReplacement());
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

    private static class TestGenerator
            implements MessageLocationReplacementGenerator<
                    String, StringMessageLocationReplacement> {

        private final MessageLocation messageLocation;
        private final List<String> payloads;
        private int index;

        TestGenerator(MessageLocation messageLocation, List<String> payloads) {
            this.messageLocation = messageLocation;
            this.payloads = payloads;
        }

        @Override
        public MessageLocation getMessageLocation() {
            return messageLocation;
        }

        @Override
        public long getNumberOfReplacements() {
            return payloads.size();
        }

        @Override
        public int compareTo(MessageLocationReplacementGenerator<?, ?> other) {
            if (other == null) {
                return 1;
            }
            return messageLocation.compareTo(other.getMessageLocation());
        }

        @Override
        public boolean hasNext() {
            return index < payloads.size();
        }

        @Override
        public StringMessageLocationReplacement next() {
            return new StringMessageLocationReplacement(messageLocation, payloads.get(index++));
        }

        @Override
        public void remove() {}

        @Override
        public void reset() {
            index = 0;
        }

        @Override
        public void close() {}
    }
}
