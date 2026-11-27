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
package org.zaproxy.addon.clienttest;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

/** Unit test for {@link SpiderCheck}. */
class SpiderCheckUnitTest {

    private static final String URL = "http://localhost:9091/client/never-loads/canary.html";

    @Test
    void shouldReportIfInTimeAndRequested() {
        // When
        String report = SpiderCheck.check(30_000, 60, URL, true);
        // Then
        assertThat(report, containsString("30s"));
        assertThat(report, containsString("was requested"));
    }

    @Test
    void shouldPassAtTheLimit() {
        SpiderCheck.check(60_000, 60, URL, true);
    }

    @Test
    void shouldFailIfTooSlow() {
        // When
        IllegalStateException e =
                assertThrows(
                        IllegalStateException.class,
                        () -> SpiderCheck.check(61_000, 60, URL, true));
        // Then
        assertThat(e.getMessage(), containsString("took too long"));
    }

    @Test
    void shouldFailIfNotRequested() {
        // When
        IllegalStateException e =
                assertThrows(
                        IllegalStateException.class,
                        () -> SpiderCheck.check(1_000, 60, URL, false));
        // Then
        assertThat(e.getMessage(), containsString("was not found"));
        assertThat(e.getMessage(), containsString("was not requested"));
    }
}
