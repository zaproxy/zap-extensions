/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.callhome;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

import net.sf.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.extension.stats.InMemoryStats;

class ExtensionCallHomeUnitTest {

    @Test
    void shouldAddFilteredGlobalStats() {
        // Given
        ExtensionCallHome ext = new ExtensionCallHome();
        InMemoryStats stats = new InMemoryStats();
        stats.counterInc("stats.ascan.one", 1);
        stats.counterInc("stats.ascan.two", 2);
        stats.counterInc("stats.ascan.three", 3);
        stats.counterInc("stats.ignore", 4);
        JSONObject data = new JSONObject();

        // When
        ext.addStatistics(data, stats);

        // Then
        assertThat(data.size(), is(equalTo(3)));
        assertThat(data.get("stats.ascan.one"), is(equalTo(1)));
        assertThat(data.get("stats.ascan.two"), is(equalTo(2)));
        assertThat(data.get("stats.ascan.three"), is(equalTo(3)));
        assertThat(data.get("stats.ignore"), is(nullValue()));
    }

    @Test
    void shouldMergeFilteredSiteStats() {
        // Given
        ExtensionCallHome ext = new ExtensionCallHome();
        InMemoryStats stats = new InMemoryStats();
        stats.counterInc("https://www.example.com", "stats.code.one", 1);
        stats.counterInc("https://www.example.com", "stats.code.two", 2);

        stats.counterInc("https://www.example.com", "stats.code.two", 2);
        stats.counterInc("https://www.example.org", "stats.code.three", 3);
        stats.counterInc("https://www.example.org", "stats.blah", 4);

        JSONObject data = new JSONObject();
        // When
        ext.addStatistics(data, stats);

        // Then
        assertThat(data.size(), is(equalTo(3)));
        assertThat(data.get("stats.code.one"), is(equalTo(1)));
        assertThat(data.get("stats.code.two"), is(equalTo(4)));
        assertThat(data.get("stats.code.three"), is(equalTo(3)));
    }
}
