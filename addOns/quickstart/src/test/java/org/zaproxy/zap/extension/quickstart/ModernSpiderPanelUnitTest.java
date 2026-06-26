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
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link ModernSpiderPanel}. */
class ModernSpiderPanelUnitTest extends TestUtils {

    private ModernSpiderPanel panel;

    @BeforeEach
    void setUp() {
        mockMessages(new ExtensionQuickStart());
        panel = new ModernSpiderPanel(null);
    }

    @Test
    void shouldStartWithZeroOptions() {
        assertThat(panel.getOptionCount(), is(equalTo(0)));
    }

    @Test
    void shouldIncrementCountWhenOptionAdded() {
        panel.addOption(optionNamed("Ajax Spider"));

        assertThat(panel.getOptionCount(), is(equalTo(1)));
    }

    @Test
    void shouldDecrementCountWhenOptionRemoved() {
        ModernSpiderOption option = optionNamed("Ajax Spider");
        panel.addOption(option);
        panel.removeOption(option);

        assertThat(panel.getOptionCount(), is(equalTo(0)));
    }

    @Test
    void shouldSupportMultipleOptions() {
        panel.addOption(optionNamed("Ajax Spider"));
        panel.addOption(optionNamed("Client Spider"));

        assertThat(panel.getOptionCount(), is(equalTo(2)));
    }

    @Test
    void shouldRestoreSpiderTypeWhenOptionAddedAfterOptionsLoaded() {
        // Simulates the normal boot order: optionsLoaded() fires on the main extension before
        // spider sub-extensions have hooked in and called addOption().
        panel.optionsLoaded(paramWithModernType("Client Spider"));

        ModernSpiderOption ajax = optionNamed("Ajax Spider");
        ModernSpiderOption client = optionNamed("Client Spider");
        panel.addOption(ajax);
        panel.addOption(client);

        assertThat(panel.getTypeComboModel().getSelectedItem(), is(equalTo(client)));
    }

    @Test
    void shouldRestoreSpiderTypeWhenOptionsLoadedAfterOptionAdded() {
        // Simulates a scenario where options are registered before optionsLoaded() fires.
        ModernSpiderOption ajax = optionNamed("Ajax Spider");
        ModernSpiderOption client = optionNamed("Client Spider");
        panel.addOption(ajax);
        panel.addOption(client);

        panel.optionsLoaded(paramWithModernType("Client Spider"));

        assertThat(panel.getTypeComboModel().getSelectedItem(), is(equalTo(client)));
    }

    @Test
    void shouldNotChangeSelectionWhenSavedTypeMatchesNoOption() {
        ModernSpiderOption ajax = optionNamed("Ajax Spider");
        panel.addOption(ajax);

        panel.optionsLoaded(paramWithModernType("Unknown Spider"));

        assertThat(panel.getTypeComboModel().getSelectedItem(), is(equalTo(ajax)));
    }

    @Test
    void shouldNotChangeSelectionWhenSavedTypeIsEmpty() {
        ModernSpiderOption ajax = optionNamed("Ajax Spider");
        ModernSpiderOption client = optionNamed("Client Spider");
        panel.addOption(ajax);
        panel.addOption(client);

        panel.optionsLoaded(paramWithModernType(""));

        assertThat(panel.getTypeComboModel().getSelectedItem(), is(equalTo(ajax)));
    }

    private static QuickStartParam paramWithModernType(String type) {
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        config.setProperty("quickstart.modern.type", type);
        QuickStartParam p = new QuickStartParam();
        p.load(config);
        return p;
    }

    private static ModernSpiderOption optionNamed(String name) {
        ModernSpiderOption option = mock(ModernSpiderOption.class);
        lenient().when(option.getName()).thenReturn(name);
        return option;
    }
}
