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
import static org.zaproxy.zap.extension.fuzz.messagelocations.MultipleMessageLocationsReplacerTestUtils.generators;
import static org.zaproxy.zap.extension.fuzz.messagelocations.MultipleMessageLocationsReplacerTestUtils.iterateAll;

import java.util.List;
import java.util.SortedSet;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.extension.fuzz.messagelocations.MultipleMessageLocationsReplacerTestUtils.RecordingReplacer;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.model.InvalidMessageException;

/** Unit test for {@link MultipleMessageLocationsPitchforkReplacer}. */
class MultipleMessageLocationsPitchforkReplacerUnitTest {

    @Test
    void shouldIterateInLockstep() throws InvalidMessageException, ReplacementException {
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
    void shouldIterateSingleLocation() throws InvalidMessageException, ReplacementException {
        // Given
        RecordingReplacer messageReplacer = new RecordingReplacer();
        MultipleMessageLocationsReplacer<Message> multipleReplacer =
                new MultipleMessageLocationsPitchforkReplacer<>();
        SortedSet<MessageLocationReplacementGenerator<?, ?>> generators =
                generators(List.of("1", "2", "3"));
        // When
        List<String> orders = iterateAll(multipleReplacer, messageReplacer, generators);
        // Then
        assertThat(orders, contains("1", "2", "3"));
    }

    @Test
    void shouldStopAtShortestList() throws InvalidMessageException, ReplacementException {
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
    void shouldReportMinListSize() {
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
}
