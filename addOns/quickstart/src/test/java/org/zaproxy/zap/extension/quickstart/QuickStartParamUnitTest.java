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
package org.zaproxy.zap.extension.quickstart;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link QuickStartParam}. */
class QuickStartParamUnitTest extends TestUtils {

    private QuickStartParam param;
    private ZapXmlConfiguration configuration;

    @BeforeEach
    void setUp() throws Exception {
        setUpZap();
        param = new QuickStartParam();
        configuration = new ZapXmlConfiguration();
        param.load(configuration);
    }

    @Test
    void shouldDefaultScanPolicyNameToEmpty() {
        assertThat(param.getScanPolicyName(), is(equalTo("")));
    }

    @Test
    void shouldSaveScanPolicyName() {
        // Given
        String policyName = "Test Policy";
        // When
        param.setScanPolicyName(policyName);
        // Then
        assertThat(param.getScanPolicyName(), is(equalTo(policyName)));
    }

    @Test
    void shouldLoadScanPolicyNameFromConfig() {
        // Given
        configuration.setProperty("quickstart.scanPolicyName", "My Policy");
        // When
        param.load(configuration);
        // Then
        assertThat(param.getScanPolicyName(), is(equalTo("My Policy")));
    }

    @Test
    void shouldDefaultAjaxSpiderSelectionToModern() {
        assertThat(
                param.getAjaxSpiderSelection(),
                is(equalTo(ModernSpiderPanel.Select.MODERN.name())));
    }

    @Test
    void shouldSaveAjaxSpiderSelection() {
        // Given
        String selection = ModernSpiderPanel.Select.ALWAYS.name();
        // When
        param.setAjaxSpiderSelection(selection);
        // Then
        assertThat(param.getAjaxSpiderSelection(), is(equalTo(selection)));
    }

    @Test
    void shouldLoadAjaxSpiderSelectionFromConfig() {
        // Given
        configuration.setProperty("quickstart.ajax.select", ModernSpiderPanel.Select.NEVER.name());
        // When
        param.load(configuration);
        // Then
        assertThat(
                param.getAjaxSpiderSelection(), is(equalTo(ModernSpiderPanel.Select.NEVER.name())));
    }

    @Test
    void shouldDefaultAjaxSpiderDefaultBrowserToFirefox() {
        assertThat(param.getAjaxSpiderDefaultBrowser(), is(equalTo("Firefox")));
    }

    @Test
    void shouldSaveAjaxSpiderDefaultBrowser() {
        // Given
        String browser = "Chrome";
        // When
        param.setAjaxSpiderDefaultBrowser(browser);
        // Then
        assertThat(param.getAjaxSpiderDefaultBrowser(), is(equalTo(browser)));
    }

    @Test
    void shouldLoadAjaxSpiderDefaultBrowserFromConfig() {
        // Given
        configuration.setProperty("quickstart.ajax.browser", "Safari");
        // When
        param.load(configuration);
        // Then
        assertThat(param.getAjaxSpiderDefaultBrowser(), is(equalTo("Safari")));
    }

    @Test
    void shouldDefaultModernSpiderTypeToEmpty() {
        assertThat(param.getModernSpiderType(), is(equalTo("")));
    }

    @Test
    void shouldSaveModernSpiderType() {
        // Given
        String type = "Ajax Spider";
        // When
        param.setModernSpiderType(type);
        // Then
        assertThat(param.getModernSpiderType(), is(equalTo(type)));
    }

    @Test
    void shouldLoadModernSpiderTypeFromConfig() {
        // Given
        configuration.setProperty("quickstart.modern.type", "Client Spider");
        // When
        param.load(configuration);
        // Then
        assertThat(param.getModernSpiderType(), is(equalTo("Client Spider")));
    }
}
