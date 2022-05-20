/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.network.internal.client;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.arrayWithSize;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.startsWith;

import org.junit.jupiter.api.Test;

/** Unit test for {@link CommonUserAgents}. */
class CommonUserAgentsUnitTest {

    @Test
    void shouldLoadUserAgents() {
        // Given / When
        String[] systems = CommonUserAgents.getSystems();
        // Then
        assertThat(systems, arrayWithSize(greaterThan(5)));
    }

    @Test
    void shouldGetUserAgentFromSystem() {
        // Given
        String system = CommonUserAgents.getSystems()[0];
        // When
        String userAgent = CommonUserAgents.getUserAgentFromSystem(system);
        // Then
        assertThat(userAgent, startsWith("Mozilla/5.0 "));
    }

    @Test
    void shouldGetSystemFromUserAgent() {
        // Given
        String originalSystem = CommonUserAgents.getSystems()[0];
        String userAgent = CommonUserAgents.getUserAgentFromSystem(originalSystem);
        // When
        String system = CommonUserAgents.getSystemFromUserAgent(userAgent);
        // Then
        assertThat(system, is(equalTo(originalSystem)));
    }
}
