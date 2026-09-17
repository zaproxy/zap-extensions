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
package org.zaproxy.addon.pscan;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.emptyString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import org.apache.commons.configuration.FileConfiguration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.zaproxy.zap.extension.pscan.ExtensionPassiveScan;
import org.zaproxy.zap.extension.pscan.PassiveScanner;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link ExtensionPassiveScan2}. */
class ExtensionPassiveScan2UnitTest extends TestUtils {

    private ExtensionPassiveScan2 extension;
    private GspmPassiveScanRegistrar gspmRegistrar;

    @BeforeEach
    void setUp() throws Exception {
        extension = new ExtensionPassiveScan2();
        mockMessages(extension);

        Model model = mock(Model.class);
        OptionsParam optionsParam = mock(OptionsParam.class);
        lenient().when(model.getOptionsParam()).thenReturn(optionsParam);
        lenient().when(optionsParam.getConfig()).thenReturn(mock(FileConfiguration.class));
        extension.initModel(model);

        gspmRegistrar = mock(GspmPassiveScanRegistrar.class);
        setField(extension, "gspmRegistrar", gspmRegistrar);
    }

    @Test
    void shouldHaveName() {
        assertThat(extension.getName(), is(equalTo("ExtensionPassiveScan2")));
    }

    @Test
    void shouldHaveUiName() {
        assertThat(extension.getUIName(), is(not(emptyString())));
    }

    @Test
    void shouldHaveDescription() {
        assertThat(extension.getDescription(), is(not(emptyString())));
    }

    @Test
    void shouldGetEmptyTagsAfterInit() {
        // Given
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class);
        when(extensionLoader.getExtension(ExtensionPassiveScan.class))
                .thenReturn(mock(ExtensionPassiveScan.class));
        Control.initSingletonForTesting(mock(Model.class), extensionLoader);
        // When
        extension.init();
        // Then
        assertThat(extension.getAutoTaggingTags(), is(empty()));
    }

    @Test
    void shouldNotifyGspmWhenPluginPassiveScanRuleAdded() {
        // Given
        PluginPassiveScanner scanner = mock(PluginPassiveScanner.class);
        given(scanner.getName()).willReturn("Test Rule");
        given(scanner.getPluginId()).willReturn(42);

        // When
        boolean added = extension.getPassiveScannersManager().add(scanner);

        // Then
        assertThat(added, is(true));
        verify(gspmRegistrar).ruleAdded(scanner);
    }

    @Test
    void shouldNotNotifyGspmWhenPluginPassiveScanRuleFailsToAdd() {
        // Given — ScanRuleManager rejects a second scanner registered under the same name.
        PluginPassiveScanner first = mock(PluginPassiveScanner.class);
        given(first.getName()).willReturn("Duplicate");
        given(first.getPluginId()).willReturn(43);
        extension.getPassiveScannersManager().add(first);
        PluginPassiveScanner duplicateName = mock(PluginPassiveScanner.class);
        given(duplicateName.getName()).willReturn("Duplicate");
        given(duplicateName.getPluginId()).willReturn(44);

        // When
        boolean added = extension.getPassiveScannersManager().add(duplicateName);

        // Then
        assertThat(added, is(false));
        verify(gspmRegistrar, never()).ruleAdded(duplicateName);
    }

    @Test
    void shouldNotNotifyGspmWhenNonPluginPassiveScannerAdded() {
        // Given
        PassiveScanner scanner = mock(PassiveScanner.class);
        given(scanner.getName()).willReturn("Plain Scanner");

        // When
        boolean added = extension.getPassiveScannersManager().add(scanner);

        // Then
        assertThat(added, is(true));
        verifyNoInteractions(gspmRegistrar);
    }

    @Test
    void shouldNotifyGspmWhenPluginPassiveScanRuleRemoved() {
        // Given
        PluginPassiveScanner scanner = mock(PluginPassiveScanner.class);
        given(scanner.getName()).willReturn("Test Rule");
        given(scanner.getPluginId()).willReturn(46);
        extension.getPassiveScannersManager().add(scanner);

        // When
        boolean removed = extension.getPassiveScannersManager().remove(scanner);

        // Then
        assertThat(removed, is(true));
        verify(gspmRegistrar).ruleRemoved(46);
    }

    @Test
    void shouldNotNotifyGspmWhenPluginPassiveScanRuleNeverAdded() {
        // Given — a scanner that was never added, so ScanRuleManager won't find it by class name
        // and none of its stubbed behaviour is actually consulted during the remove attempt.
        PluginPassiveScanner scanner = mock(PluginPassiveScanner.class);

        // When
        boolean removed = extension.getPassiveScannersManager().remove(scanner);

        // Then
        assertThat(removed, is(false));
        verify(gspmRegistrar, never()).ruleRemoved(anyInt());
    }

    private static void setField(ExtensionPassiveScan2 target, String name, Object value)
            throws Exception {
        Field field = ExtensionPassiveScan2.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(target, value);
    }
}
