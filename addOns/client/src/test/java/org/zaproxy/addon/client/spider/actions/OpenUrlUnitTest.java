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
package org.zaproxy.addon.client.spider.actions;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openqa.selenium.WebDriver;
import org.zaproxy.zap.extension.stats.InMemoryStats;
import org.zaproxy.zap.utils.Stats;

/** Unit test for {@link OpenUrl}. */
class OpenUrlUnitTest {

    private InMemoryStats stats;

    @BeforeEach
    void setUp() {
        stats = new InMemoryStats();
        Stats.addListener(stats);
    }

    @AfterEach
    void tearDown() {
        Stats.removeListener(stats);
    }

    @Test
    void shouldThrowIfUrlIsNull() {
        assertThrows(NullPointerException.class, () -> new OpenUrl(null));
    }

    @Test
    void shouldOpenUrlOnRun() {
        // Given
        String url = "http://example.com/page";
        OpenUrl action = new OpenUrl(url);
        WebDriver wd = mock(WebDriver.class);

        // When
        action.run(wd);

        // Then
        verify(wd).get(url);
        assertThat(stats.getStat("stats.client.spider.action.url"), is(1L));
    }
}
