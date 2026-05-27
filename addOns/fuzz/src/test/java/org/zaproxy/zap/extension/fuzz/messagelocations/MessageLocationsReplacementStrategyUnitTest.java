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
import static org.hamcrest.Matchers.is;

import org.junit.jupiter.api.Test;

/** Unit test for {@link MessageLocationsReplacementStrategy}. */
class MessageLocationsReplacementStrategyUnitTest {

    @Test
    void shouldReturnClusterBombForClusterBombConfigId() {
        assertThat(
                MessageLocationsReplacementStrategy.getValue("clusterBomb"),
                is(MessageLocationsReplacementStrategy.CLUSTER_BOMB));
    }

    @Test
    void shouldReturnPitchforkForPitchforkConfigId() {
        assertThat(
                MessageLocationsReplacementStrategy.getValue("pitchfork"),
                is(MessageLocationsReplacementStrategy.PITCHFORK));
    }

    @Test
    void shouldReturnClusterBombForLegacyDepthConfigId() {
        assertThat(
                MessageLocationsReplacementStrategy.getValue("depth"),
                is(MessageLocationsReplacementStrategy.CLUSTER_BOMB));
    }

    @Test
    void shouldReturnPitchforkForLegacyBreadthConfigId() {
        assertThat(
                MessageLocationsReplacementStrategy.getValue("breadth"),
                is(MessageLocationsReplacementStrategy.PITCHFORK));
    }

    @Test
    void shouldDefaultToClusterBombForUnknownConfigId() {
        assertThat(
                MessageLocationsReplacementStrategy.getValue("unknown"),
                is(MessageLocationsReplacementStrategy.CLUSTER_BOMB));
    }
}
