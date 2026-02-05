/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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

import java.util.HashMap;
import java.util.Map;
import net.sf.json.JSONObject;
import org.junit.jupiter.api.Test;

/** Unit Tests for {@code ClickElement} */
class ClickElementUnitTest {

    @Test
    void shouldSupportElementWithInteractiveAriaRole() {
        // Given
        Map<String, String> data = new HashMap<>();
        data.put("tagName", "DIV");
        data.put("id", "");
        data.put("role", "button");
        JSONObject ariaObj = new JSONObject();
        ariaObj.put("aria-label", "Submit");
        data.put("ariaIdentification", ariaObj.toString());

        // When
        boolean supported = ClickElement.isSupported(href -> true, data);

        // Then
        assertThat(supported, is(true));
    }

    @Test
    void shouldSupportElementWithIdAndRole() {
        // Given
        Map<String, String> data = new HashMap<>();
        data.put("tagName", "DIV");
        data.put("id", "my-aria-button");
        data.put("role", "button");

        // When
        boolean supported = ClickElement.isSupported(href -> true, data);

        // Then
        assertThat(supported, is(true));
    }

    @Test
    void shouldNotSupportElementWithOnlyAriaAttribute() {
        // Given
        Map<String, String> data = new HashMap<>();
        data.put("tagName", "DIV");
        data.put("id", "");
        JSONObject ariaObj = new JSONObject();
        ariaObj.put("aria-pressed", "false");
        data.put("ariaIdentification", ariaObj.toString());

        // When
        boolean supported = ClickElement.isSupported(href -> true, data);

        // Then
        assertThat(supported, is(false));
    }

    @Test
    void shouldNotSupportElementWithoutAriaRoleOrAttribute() {
        // Given
        Map<String, String> data = new HashMap<>();
        data.put("tagName", "DIV");
        data.put("id", "test-id");

        // When
        boolean supported = ClickElement.isSupported(href -> true, data);

        // Then
        assertThat(supported, is(false));
    }

    @Test
    void shouldSupportStandardButton() {
        // Given
        Map<String, String> data = new HashMap<>();
        data.put("tagName", "BUTTON");
        data.put("id", "btn-id");

        // When
        boolean supported = ClickElement.isSupported(href -> true, data);

        // Then
        assertThat(supported, is(true));
    }

    @Test
    void shouldSupportStandardLink() {
        // Given
        Map<String, String> data = new HashMap<>();
        data.put("tagName", "A");
        data.put("id", "link-id");
        data.put("href", "https://example.com");

        // When
        boolean supported = ClickElement.isSupported(href -> true, data);

        // Then
        assertThat(supported, is(true));
    }

    @Test
    void shouldNotSupportLinkOutOfScope() {
        // Given
        Map<String, String> data = new HashMap<>();
        data.put("tagName", "A");
        data.put("id", "link-id");
        data.put("href", "https://example.com");

        // When
        boolean supported = ClickElement.isSupported(href -> false, data);

        // Then
        assertThat(supported, is(false));
    }
}
