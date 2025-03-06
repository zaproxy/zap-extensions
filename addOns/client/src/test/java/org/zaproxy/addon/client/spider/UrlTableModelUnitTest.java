/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.client.spider;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.hasSize;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link UrlTableModel}. */
class UrlTableModelUnitTest extends TestUtils {

    private UrlTableModel model;

    @BeforeAll
    static void setupAll() {
        mockMessages(new ExtensionClientIntegration());
    }

    @BeforeEach
    void setup() {
        model = new UrlTableModel();
    }

    @Test
    void shouldAddUrls() {
        // Given
        String urlA = "https://example.org/path/a";
        String urlB = "https://example.org/path/b";
        // When
        model.addScanResult(urlA);
        model.addScanResult(urlB);
        // Then
        assertThat(model.getAddedNodes(), contains(urlA, urlB));
    }

    @Test
    void shouldNotAddUrlAlreadyAdded() {
        // Given
        String url = "https://example.org";
        model.addScanResult(url);
        // When
        model.addScanResult(url);
        // Then
        assertThat(model.getAddedNodes(), hasSize(1));
    }
}
